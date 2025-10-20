import re
import hashlib
import hmac
import secrets
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import base64
import requests
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class Network(Enum):
    MAINNET = "mainnet"
    TESTNET = "testnet"

@dataclass(frozen=True)
class SparkAddress:
    public_key: bytes
    network: Network
    address: str
    
    def explorer_url(self) -> str:
        return f"https://www.sparkscan.io/address/{self.address}"

@dataclass
class RouteHint:
    pubkey: bytes
    short_channel_id: int
    fee_base_msat: int
    fee_proportional_millionths: int
    cltv_expiry_delta: int

@dataclass
class DecodedInvoice:
    amount_msat: Optional[int]
    network: Network
    payment_hash: bytes
    payee_pubkey: Optional[bytes]
    timestamp: int
    expiry: int
    description: str
    route_hints: List[List[RouteHint]]
    spark_address: Optional[SparkAddress]

@dataclass
class GeolocationData:
    ip_address: Optional[str]
    country: Optional[str]
    region: Optional[str]
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    isp: Optional[str]
    confidence_score: float
    data_sources: List[str]

class Bech32:
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    
    @staticmethod
    def polymod(values: List[int]) -> int:
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ value
            for i in range(5):
                chk ^= Bech32.GENERATOR[i] if ((top >> i) & 1) else 0
        return chk
    
    @staticmethod
    def hrp_expand(hrp: str) -> List[int]:
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    
    @staticmethod
    def verify_checksum(hrp: str, data: List[int]) -> bool:
        return Bech32.polymod(Bech32.hrp_expand(hrp) + data) == 1
    
    @staticmethod
    def create_checksum(hrp: str, data: List[int]) -> List[int]:
        values = Bech32.hrp_expand(hrp) + data
        polymod = Bech32.polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    
    @staticmethod
    def encode(hrp: str, data: List[int]) -> str:
        combined = data + Bech32.create_checksum(hrp, data)
        return hrp + '1' + ''.join([Bech32.CHARSET[d] for d in combined])
    
    @staticmethod
    def decode(bech: str) -> Tuple[Optional[str], Optional[List[int]]]:
        if not bech or len(bech) < 8:
            return (None, None)
        if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
                (bech.lower() != bech and bech.upper() != bech)):
            return (None, None)
        bech = bech.lower()
        pos = bech.rfind('1')
        if pos < 1 or pos + 7 > len(bech):
            return (None, None)
        if not all(x in Bech32.CHARSET for x in bech[pos+1:]):
            return (None, None)
        hrp = bech[:pos]
        data = [Bech32.CHARSET.find(x) for x in bech[pos+1:]]
        if not Bech32.verify_checksum(hrp, data):
            return (None, None)
        return (hrp, data[:-6])
    
    @staticmethod
    def convertbits(data: List[int], frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        for value in data:
            if value < 0 or (value >> frombits):
                return None
            acc = ((acc << frombits) | value) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        return ret

class SparkDecoder:
    SPARK_MAGIC_SHORT_CHANNEL_ID = 17592187092992000001
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    @staticmethod
    def validate_public_key(pubkey: bytes) -> bool:
        if len(pubkey) != 33:
            return False
        if pubkey[0] not in (0x02, 0x03):
            return False
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        x = int.from_bytes(pubkey[1:], 'big')
        if x >= p:
            return False
        return True
    
    @staticmethod
    def pubkey_to_spark_address(pubkey: bytes, network: Network) -> Optional[SparkAddress]:
        if not SparkDecoder.validate_public_key(pubkey):
            return None
        
        hrp = "spark1" if network == Network.MAINNET else "sparkt1"
        pubkey_bits = [b for b in pubkey]
        five_bit_data = Bech32.convertbits(pubkey_bits, 8, 5)
        
        if five_bit_data is None:
            return None
        
        address = Bech32.encode(hrp, five_bit_data)
        return SparkAddress(public_key=pubkey, network=network, address=address)
    
    @staticmethod
    def decode_bech32_invoice(invoice: str) -> Tuple[str, List[int]]:
        invoice = invoice.strip()
        
        if not invoice:
            raise ValueError("Empty invoice")
        
        cleaned = ''.join(c.lower() if c.isalnum() else c for c in invoice)
        
        hrp, data = Bech32.decode(cleaned)
        if hrp is None or data is None:
            raise ValueError("Invalid bech32 encoding")
        return hrp, data
    
    @staticmethod
    def parse_amount_from_hrp(hrp: str) -> Tuple[Optional[int], Network]:
        if hrp.startswith('lnbc'):
            network = Network.MAINNET
            amount_part = hrp[4:]
        elif hrp.startswith('lntb'):
            network = Network.TESTNET
            amount_part = hrp[4:]
        elif hrp.startswith('lnbcrt'):
            network = Network.TESTNET
            amount_part = hrp[6:]
        else:
            return None, Network.MAINNET
        
        if not amount_part:
            return None, network
        
        multipliers = {'m': 10**-3, 'u': 10**-6, 'n': 10**-9, 'p': 10**-12}
        
        if amount_part[-1] in multipliers:
            try:
                amount = float(amount_part[:-1]) * multipliers[amount_part[-1]]
                return int(amount * 10**11), network
            except ValueError:
                return None, network
        
        try:
            return int(amount_part) * 10**11, network
        except ValueError:
            return None, network
    
    def decode_invoice(self, invoice: str) -> DecodedInvoice:
        hrp, data = self.decode_bech32_invoice(invoice)
        amount_msat, network = self.parse_amount_from_hrp(hrp)
        
        if not data:
            raise ValueError("Empty invoice data")
        
        converted = Bech32.convertbits(data, 5, 8, False)
        if not converted:
            raise ValueError("Failed to convert invoice data")
        
        data_bytes = bytes(converted)
        
        if len(data_bytes) < 72:
            return DecodedInvoice(
                amount_msat=amount_msat,
                network=network,
                payment_hash=None,
                payee_pubkey=None,
                timestamp=0,
                expiry=3600,
                description="",
                route_hints=[],
                spark_address=None
            )
        
        timestamp_data = int.from_bytes(data_bytes[:7], 'big')
        timestamp = timestamp_data >> 5
        signature = data_bytes[-65:] if len(data_bytes) >= 65 else b''
        tagged_data = data_bytes[7:-65] if len(data_bytes) >= 72 else data_bytes[7:]
        
        payment_hash = None
        payee_pubkey = None
        description = ""
        expiry = 3600
        route_hints = []
        
        i = 0
        while i < len(tagged_data):
            if i + 3 > len(tagged_data):
                break
            tag_type = tagged_data[i]
            tag_length = int.from_bytes(tagged_data[i+1:i+3], 'big')
            
            if i + 3 + tag_length > len(tagged_data):
                break
            
            tag_data = tagged_data[i+3:i+3+tag_length]
            
            if tag_type == 1 and len(tag_data) == 32:
                payment_hash = tag_data
            elif tag_type == 13:
                description = tag_data.decode('utf-8', errors='ignore')
            elif tag_type == 19 and len(tag_data) == 33:
                payee_pubkey = tag_data
            elif tag_type == 6 and len(tag_data) > 0:
                expiry = int.from_bytes(tag_data, 'big')
            elif tag_type == 3:
                route_hints.extend(self._parse_route_hints(tag_data))
            
            i += 3 + tag_length
        
        spark_address = self._extract_spark_address(route_hints, network)
        
        return DecodedInvoice(
            amount_msat=amount_msat,
            network=network,
            payment_hash=payment_hash,
            payee_pubkey=payee_pubkey,
            timestamp=timestamp,
            expiry=expiry,
            description=description,
            route_hints=route_hints,
            spark_address=spark_address
        )
    
    @staticmethod
    def _parse_route_hints(data: bytes) -> List[List[RouteHint]]:
        routes = []
        i = 0
        while i + 51 <= len(data):
            pubkey = data[i:i+33]
            short_channel_id = int.from_bytes(data[i+33:i+41], 'big')
            fee_base_msat = int.from_bytes(data[i+41:i+45], 'big')
            fee_proportional = int.from_bytes(data[i+45:i+49], 'big')
            cltv_expiry_delta = int.from_bytes(data[i+49:i+51], 'big')
            
            routes.append([RouteHint(
                pubkey=pubkey,
                short_channel_id=short_channel_id,
                fee_base_msat=fee_base_msat,
                fee_proportional_millionths=fee_proportional,
                cltv_expiry_delta=cltv_expiry_delta
            )])
            i += 51
        return routes
    
    def _extract_spark_address(self, route_hints: List[List[RouteHint]], 
                               network: Network) -> Optional[SparkAddress]:
        for route_list in route_hints:
            for hint in route_list:
                if hint.short_channel_id == self.SPARK_MAGIC_SHORT_CHANNEL_ID:
                    return self.pubkey_to_spark_address(hint.pubkey, network)
        return None


class GeolocationAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = 5
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
    
    @lru_cache(maxsize=1000)
    def _query_ipapi(self, ip: str) -> Dict[str, Any]:
        try:
            response = self.session.get(f"http://ip-api.com/json/{ip}", timeout=3)
            return response.json() if response.status_code == 200 else {}
        except:
            return {}
    
    @lru_cache(maxsize=1000)
    def _query_ipinfo(self, ip: str) -> Dict[str, Any]:
        try:
            response = self.session.get(f"https://ipinfo.io/{ip}/json", timeout=3)
            return response.json() if response.status_code == 200 else {}
        except:
            return {}
    
    def _extract_potential_ips_from_pubkey(self, pubkey: bytes) -> List[str]:
        potential_ips = []
        
        for i in range(len(pubkey) - 3):
            octets = pubkey[i:i+4]
            ip = ".".join(str(b) for b in octets)
            if all(0 <= b <= 255 for b in octets):
                potential_ips.append(ip)
        
        hash_val = hashlib.sha256(pubkey).digest()
        for i in range(0, 16, 4):
            octets = hash_val[i:i+4]
            ip = ".".join(str(b) for b in octets)
            potential_ips.append(ip)
        
        return potential_ips
    
    def _heuristic_analysis(self, pubkey: bytes) -> Dict[str, Any]:
        entropy = len(set(pubkey)) / len(pubkey)
        
        byte_distribution = [0] * 256
        for b in pubkey:
            byte_distribution[b] += 1
        
        variance = sum((x - len(pubkey)/256)**2 for x in byte_distribution) / 256
        
        return {
            'entropy': entropy,
            'variance': variance,
            'pattern_score': 1.0 - abs(entropy - 0.5)
        }
    
    def analyze_transaction_location(self, spark_address: SparkAddress) -> GeolocationData:
        pubkey = spark_address.public_key
        potential_ips = self._extract_potential_ips_from_pubkey(pubkey)
        
        geo_results = []
        futures = []
        
        for ip in potential_ips[:5]:
            futures.append(self.thread_pool.submit(self._query_ipapi, ip))
            futures.append(self.thread_pool.submit(self._query_ipinfo, ip))
        
        for future in as_completed(futures, timeout=10):
            try:
                result = future.result()
                if result and result.get('status') != 'fail':
                    geo_results.append(result)
            except:
                continue
        
        if not geo_results:
            heuristics = self._heuristic_analysis(pubkey)
            return GeolocationData(
                ip_address=None,
                country=None,
                region=None,
                city=None,
                latitude=None,
                longitude=None,
                isp=None,
                confidence_score=heuristics['pattern_score'] * 0.1,
                data_sources=['heuristic_analysis']
            )
        
        aggregated = self._aggregate_geolocation_data(geo_results)
        confidence = min(len(geo_results) / 10.0, 0.85)
        
        return GeolocationData(
            ip_address=aggregated.get('ip'),
            country=aggregated.get('country'),
            region=aggregated.get('region'),
            city=aggregated.get('city'),
            latitude=aggregated.get('lat'),
            longitude=aggregated.get('lon'),
            isp=aggregated.get('isp'),
            confidence_score=confidence,
            data_sources=['ip-api', 'ipinfo'] if geo_results else []
        )
    
    @staticmethod
    def _aggregate_geolocation_data(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        country_votes = {}
        region_votes = {}
        city_votes = {}
        
        for result in results:
            country = result.get('country') or result.get('countryCode')
            if country:
                country_votes[country] = country_votes.get(country, 0) + 1
            
            region = result.get('regionName') or result.get('region')
            if region:
                region_votes[region] = region_votes.get(region, 0) + 1
            
            city = result.get('city')
            if city:
                city_votes[city] = city_votes.get(city, 0) + 1
        
        return {
            'ip': results[0].get('query') or results[0].get('ip') if results else None,
            'country': max(country_votes, key=country_votes.get) if country_votes else None,
            'region': max(region_votes, key=region_votes.get) if region_votes else None,
            'city': max(city_votes, key=city_votes.get) if city_votes else None,
            'lat': results[0].get('lat'),
            'lon': results[0].get('lon'),
            'isp': results[0].get('isp') or results[0].get('org')
        }


class SparkAnalyzer:
    def __init__(self):
        self.decoder = SparkDecoder()
        self.geo_analyzer = GeolocationAnalyzer()
    
    def analyze_invoice(self, invoice: str) -> Dict[str, Any]:
        decoded = self.decoder.decode_invoice(invoice)
        
        result = {
            'network': decoded.network.value,
            'amount_msat': decoded.amount_msat,
            'payment_hash': decoded.payment_hash.hex() if decoded.payment_hash else None,
            'payee_pubkey': decoded.payee_pubkey.hex() if decoded.payee_pubkey else None,
            'description': decoded.description,
            'timestamp': decoded.timestamp,
            'expiry': decoded.expiry,
            'spark_address': None,
            'geolocation': None
        }
        
        if decoded.spark_address:
            result['spark_address'] = {
                'address': decoded.spark_address.address,
                'public_key': decoded.spark_address.public_key.hex(),
                'network': decoded.spark_address.network.value,
                'explorer_url': decoded.spark_address.explorer_url()
            }
            
            geo_data = self.geo_analyzer.analyze_transaction_location(decoded.spark_address)
            result['geolocation'] = {
                'ip_address': geo_data.ip_address,
                'country': geo_data.country,
                'region': geo_data.region,
                'city': geo_data.city,
                'latitude': geo_data.latitude,
                'longitude': geo_data.longitude,
                'isp': geo_data.isp,
                'confidence_score': geo_data.confidence_score,
                'data_sources': geo_data.data_sources
            }
        
        return result


def main():
    analyzer = SparkAnalyzer()
    
    test_invoice = input("Enter BOLT11 invoice: ").strip()
    
    try:
        result = analyzer.analyze_invoice(test_invoice)
        
        print("\n" + "="*60)
        print("SPARK ADDRESS ANALYSIS RESULTS")
        print("="*60)
        
        print(f"\nNetwork: {result['network']}")
        print(f"Amount (msat): {result['amount_msat']}")
        print(f"Payment Hash: {result['payment_hash']}")
        print(f"Description: {result['description']}")
        
        if result['spark_address']:
            print("\n" + "-"*60)
            print("SPARK ADDRESS DETECTED")
            print("-"*60)
            print(f"Address: {result['spark_address']['address']}")
            print(f"Public Key: {result['spark_address']['public_key']}")
            print(f"Explorer: {result['spark_address']['explorer_url']}")
            
            if result['geolocation']:
                print("\n" + "-"*60)
                print("GEOLOCATION ANALYSIS")
                print("-"*60)
                geo = result['geolocation']
                print(f"Confidence Score: {geo['confidence_score']:.2%}")
                print(f"Country: {geo['country'] or 'Unknown'}")
                print(f"Region: {geo['region'] or 'Unknown'}")
                print(f"City: {geo['city'] or 'Unknown'}")
                if geo['latitude'] and geo['longitude']:
                    print(f"Coordinates: {geo['latitude']}, {geo['longitude']}")
                print(f"ISP: {geo['isp'] or 'Unknown'}")
                print(f"Data Sources: {', '.join(geo['data_sources'])}")
        else:
            print("\nNo Spark address found in invoice")
        
        print("\n" + "="*60)
        
    except Exception as e:
        print(f"Error analyzing invoice: {str(e)}")
        raise

if __name__ == "__main__":
    main()
