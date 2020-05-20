ABOUT
-----------
This script will extract and parse the key vulnerability details requested in the command-line arguments, or simply for all pages in the `samples` variable if these args are not specified.


HOW TO RUN
-----------
To run this script, run:
`python3 parser.py -i <URL of page to parse> -o <output JSON name>`

Example:
`python3 parser.py -i https://helpx.adobe.com/security/products/magento/apsb20-02.html -o sample1`


DEPENDENCIES
-----------
You will need the bs4 and requests packages installed, as detailed in requirements.txt.

