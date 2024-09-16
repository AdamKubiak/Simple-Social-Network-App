# PowerShell script to set FLASK_APP environment variable and run Flask
# $env:FLASK_APP = ".\flasky.py"

$env:MAIL_USERNAME=""
$env:SECRET_KEY=""

$env:FLASK_APP="flasky.py"
$env:FLASK_DEBUG=1
$env:FLASK_CONFIG="production"