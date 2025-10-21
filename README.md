- You'll need Python 3.8 or newer. The tool depends on the requests library for API calls, but everything else uses the standard library.

# Usage

- The simplest way to run it is directly from the command line:

          python decoder.py

- You'll be prompted to paste a ***BOLT11 invoice***. The tool will analyze it and display results including network type, payment details, and if present, the extracted Spark address with geolocation data.

  ![invoice](https://github.com/user-attachments/assets/ca674f09-5e16-4e6e-b2a8-e5907b7ab7f8)

- This project was inspired by the Rust implementation by [benthecarman](https://github.com/benthecarman/spark-invoice-doxxer)
- [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Alb4don/SparkDecoder)
