$folderName = "c:\$(([GUID]::NewGuid()).Guid)"

md $folderName | Out-Null

#Write-Host "New Base $($folderName)"

$baseP = $folderName

$py =  "$($PSScriptRoot )\DoCAStuff.py"

$did = & python $py --mode NewRootCA  --name "Gamache Trust Root 2018" --validfrom janOf2018 --validto janOf2048 --keysize 521 --pathlength 2 --ncallowed "pkilab.markgamache.com,mtlspkilab.markgamache.com,bankofplace" --basepath "$($baseP)\" --cps "http://birds.com" --kus "key_encipherment,digital_signature" --ekus "CODE_SIGNING,SERVER_AUTH"


$did = & python $py --mode NewSubCA  --name "HullaHoop" --signer "Gamache Trust Root 2018" --validfrom janOf2018 --validto janOf2048 --keysize 2048 --pathlength 2 --ncallowed "pkilab.markgamache.com,mtlspkilab.markgamache.com,bankofplace" --basepath "$($baseP)\" --cps "http://birds.com" # --kus "key_encipherment,digital_signature" # --ekus "CODE_SIGNING,SERVER_AUTH"

$did = & python $py --mode NewLeafTLS --basepath "$($baseP)\" --name "gustice.pkilab.markgamache.com" --signer "HullaHoop" --validfrom dtMinusTenMin --validto dtPlusOneYear --keysize 256  --kus "key_encipherment,digital_signature" --ekus "CODE_SIGNING,SERVER_AUTH" --cps "http://birds.com"



$caBack = $did | ConvertFrom-Json

#$caBack

openssl x509 -noout -text -in "$($caBack.DERFile)" -inform DER

rm $folderName -Force -Recurse

write-host