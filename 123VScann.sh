#!/bin/sh

# 123VScann
echo ""
echo ========================== 123VScan by 1twodrei ==========================
echo 1twodrei ...
echo ""

######################### Vars:
 # Intern:
 subdoms=""
 endpoints="http://www.w3.org/2000/svg http://www.robotstxt.org/robotstxt.html http://www.sitemaps.org/schemas/sitemap/0.9"
 alreadydeepenumedendpoints=""
 interestingrequests=""
 irrelevantendpoints=""
 seleniumouturls=""
 DNS_nr=0
 
 # Static:
  # txtFiles:
  subdomtxt=""
  subdomtxtxxl=""
  dirtxt=""
  dirtxtxxl=""
  customdirstxt="Customdirstxt.txt"
  filetosavepotentialsubtakesin=""
  xsshunterurl="$(cat Xsshunterurl.txt)" # cat from file!
  # Keywords:
  subtakekeywordstxt="$(cat Subtakekeywordstxt.txt)"
  vulnerabilityindicatorkeywords="" # e.g. loginpage known to be vulnerable (research on h1 & other sources) OR simply xxx123456789 for txt injection, HTML I., SSTI,...


 # User defined:
 echo What is your target?
 read maintarget
 subdoms="$maintarget"
 echo Do you want to include subdomains?   [yes/no]
 read includesubdomains
 if [[ $includesubdomains = *"yes"* ]]; then
   includesubdomains="yes"
 else
   includesubdomains="no"
 fi
 echo Which urls are out of scope?   [Recommended format: subdomain.domain or subdomain.domain/dir] [Seperate with the space char]
 read outofscope
 echo How many layers for the deep enum? [Recommended: 3]
 read deepenumlayers
 echo Your session cookie?   [Form: "name=value"]
 read mainsessioncookie
 echo Your header to identify yourself? [e.g. "X-hone: h1Usename"] [If you dont need one press enter]
 read mainidentifyheader
 
 
 
 ####### Debugging:
#maintarget="shopify.com"
maintarget="tradingview.com"
includesubdomains="no"
subdoms="$maintarget"
#outofscope="email.shopify.com cdn.shopify.com investors.shopify.com go.shopify.com livechat.shopify.com community.shopify.com partner-training.shopify.com"
outofscope="support.hackerone.com docs.hackerone.com"
deepenumlayers="3"
#xsshunterurl="3twoeins.xss.ht"
mainsessioncookie="test=test"
mainidentifyheader="X-test: test"
h1username="1twodrei"
######################### Vars END

### Info:
echo ============================================================
echo Target: . . . . . . . . $maintarget
echo Subdomains included:. . $includesubdomains
echo Out of scope: . . . . . $outofscope
echo Enumeration layers: . . $deepenumlayers
echo Main sessioncookie: . . $mainsessioncookie
echo Identifier header:. . . $mainidentifyheader
echo ============================================================
sleep 1
### Info END

############################################# Functions:
#### Small functions:
### pyrequests_scrape_endpoint
pyrequests_scrape_endpoint () {
echo "pyrequests_scrape_endpoint for $1"
commonpathstoignore=""
scanurl_until_first_slash="$1"
filter0=""
filter="//"
filter2="/"
filter3=" "
chopped_scanurl="${scanurl_until_first_slash/$filter/ö}"
chopped_scanurl="${chopped_scanurl/$filter2/$filter3}"
chopped_scanurl="${chopped_scanurl/ö/$filter}"

scanurl_until_first_slash_found=0
for url_until in $chopped_scanurl
do
   if [[ "$url_until" = *"/"* ]]; then
      if [[ $scanurl_until_first_slash_found = 0 ]]; then
         scanurl_until_first_slash="$url_until"
         scanurl_until_first_slash_found=1
      fi
   fi
done

filter4="http://"
filter5="https://"
scanurl_until_first_slash="${scanurl_until_first_slash/$filter4/$filter0}"
innerurl="${scanurl_until_first_slash/$filter5/$filter0}"

pyrequestsout=$(exec python3 -c "
import requests

headers = {'Accept': '*/*', 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0', 'X-Hackerone': '$h1username'}
try:
   r = requests.get('$1', timeout=3, headers=headers)
   for key, val in r.headers.items():
       headerinfo = (key, ':', val)
       headerinfo = str(headerinfo)
       print(headerinfo.replace('\"', \" \").replace(')', \"  \").replace(';', \" \").replace('\'', \" \").replace('^', \" \").replace('(', \" \").replace('{', \" \").replace('}', \" \").replace('@', \" \"))
   print('============')
   rtext = str(r.text)
   print(rtext.replace('\"', \" \").replace(')', \" \").replace(';', \" \").replace('\'', \" \").replace('^', \" \").replace('(', \" \").replace('{', \" \").replace('}', \" \").replace('@', \" \"))
except:
   print(\" \")
")

pyrequestsout=$(echo $pyrequestsout | tr '>' ' ' | tr '<' ' ')
irrelevantresults=0


for url in $pyrequestsout
do
   if [[ $irrelevantresults -lt 40 ]]; then
      if [[ "$url" = *"http://"* ]] || [[ "$url" = *"https://"* ]] || [[ "$url" = *"$innerurl"* ]]; then
         if [[ "$url" = *"http://"* ]] || [[ "$url" = *"https://"* ]]; then
            n=n
         else
            url="https://$url"
         fi
         url_maindomain="${url/$filter/ö}"
         url_maindomain="$(echo $url_maindomain | cut -d "/" -f1 )"
         url_maindomain="${url_maindomain/ö/$filter}"
         
         endpoint_already_found=0
         commonendpointpath=0
         
         if [[ "$endpoints" = *"$url_maindomain"* ]]; then
            n="url_maindomain already known"
         else
            #url_hijacking_now $url_maindomain $url $1
            endpoints="$endpoints $url_maindomain"
         fi
         
         for endpoint in $endpoints
         do
            compareurlforcommons="${endpoint/$filter/ö}"
            compareurlforcommons="$(echo $compareurlforcommons | rev | cut -d "/" -f2- | rev )"
            compareurlforcommons="${compareurlforcommons/ö/$filter}"
            if [[ "$url" = "$endpoint" ]]; then
               endpoint_already_found=1
            elif [[ "$url" = *"$compareurlforcommons"* ]]; then
               (( commonendpointpath++ ))
            fi
            #if [[ "$compareurlforcommons" = "$endpoint" ]]; then
            #   endpoint_already_found=1
         done
         if [[ $endpoint_already_found = 0 ]] && [[ $commonendpointpath -lt 10 ]]; then
            endpoints="$endpoints $url"
            if [[ "$endpoints" = *"$compareurlforcommons"* ]]; then
               n=n
            else
               endpoints="$endpoints $compareurlforcommons"
            fi
            compareurlforcommons="${url/$filter/ö}"
            compareurlforcommons="$(echo $compareurlforcommons | cut -d "/" -f1 )"
            compareurlforcommons="${compareurlforcommons/ö/$filter}"
            if [[ "$endpoints" = *"$compareurlforcommons"* ]]; then
               n=n
            else
               endpoints="$endpoints $compareurlforcommons"
            fi
            compareurlforcommons="${url/$filter/ö}"
            compareurlforcommons="$(echo $compareurlforcommons | cut -d "/" -f1 )"
            compareurlforcommons="${compareurlforcommons/ö/$filter}"
            if [[ "$endpoints" = *"$compareurlforcommons"* ]]; then
               n=n
            else
               endpoints="$endpoints $compareurlforcommons"
            fi
            echo $url $commonendpointpath
         elif [[ $endpoint_already_found = 0 ]]; then
            (( irrelevantresults++ ))
            echo "irrelevantresults: $irrelevantresults"
         fi
      fi
   fi
done


   
}

### selenium_scrape_endpoint
selenium_scrape_endpoint () {
if [[ "$alreadydeepenumedendpoints" = *" $1 "* ]]; then
   echo "alreadydeepenumed endpoint $1"
else
statuscode="$(timeout 8 python3 -c "
import requests

headers = {'Accept': '*/*', 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0'}
try:
   r = requests.get('$1', timeout=3, headers=headers)
   print(r.status_code)
   print(r.text).replace(\"\\r\", \" \").replace(\"\\n\", \" \")
except:
   print(\"\")
   ")"
vulnerabilityindicatorkeyword_nr=0
for vulnerabilityindicatorkeyword in $vulnerabilityindicatorkeywords
do
   if [[ "$statuscode" = *"$vulnerabilityindicatorkeyword"* ]]; then
      potential_other_vulnerabilitys="$potential_other_vulnerabilitys At.$1.Other_vulnerability_NR:.$vulnerabilityindicatorkeyword_nr [keyword:.$vulnerabilityindicatorkeyword]"
      echo ===============  Potential finding:  ===============
      echo Other vulnerability: "At $1 Other_vulnerability_NR: $vulnerabilityindicatorkeyword_nr [keyword: $vulnerabilityindicatorkeyword]"
      echo ====================================================
   fi
done

if [[ "$statuscode" = "403"* ]]; then
   status_code_bypass $1
fi

if [[ "$statuscode" = "2"* ]] || [[ "$statuscode" = "3"* ]] || [[ "$statuscode" = "4"* ]]; then

scanurl_until_first_slash="$1"
filter="//"
filter2="/"
filter3=" "
chopped_scanurl="${scanurl_until_first_slash/$filter/ö}"
chopped_scanurl="${chopped_scanurl/$filter2/$filter3}"
chopped_scanurl="${chopped_scanurl/ö/$filter}"

scanurl_until_first_slash_found=0
for url_until in $chopped_scanurl
do
   if [[ "$url_until" = *"/"* ]]; then
      if [[ $scanurl_until_first_slash_found = 0 ]]; then
         scanurl_until_first_slash="$url_until"
         scanurl_until_first_slash_found=1
      fi
   fi
done
#timeout 10s
echo "Selenum for $1"
seleniumout=$(timeout 12 python3 -c "
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
#import requests
#specify where your chrome driver present in your pc
#PATH=r\"C:\Users\educative\Documents\chromedriver\chromedriver.exe\"
browser = webdriver.Safari()
browser.implicitly_wait(1)
allrequests = \"ÄÄÄ\"
allurls = \"\"
spacefiller = \"ö\"
space = \" \"
try:
   browser.get(\"$1\")
   all_links = browser.find_elements(By.XPATH, '//*[@href]')
   all_directurls = browser.find_elements(By.XPATH, '//*[@url]')
   all_sources = browser.find_elements(By.XPATH, '//*[@src]')
   all_sourcedocs = browser.find_elements(By.XPATH, '//*[@srcdoc]')
   all_scripts = browser.find_elements(By.TAG_NAME, 'script')
   all_forms = browser.find_elements(By.TAG_NAME, 'form')


   for link in all_links:
   #extract url from href attribute
      url = link.get_attribute('href').replace(\"\\r\", \" \").replace(\"\\n\", \" \")
      #print(url)
      allurls = allurls + space + url

   for surce in all_sources:
   #extract url from href attribute
      srcurl = surce.get_attribute('src').replace(\"\\r\", \" \").replace(\"\\n\", \" \")
      #print(srcurl)
      allurls = allurls + space + srcurl

    #send request to the url and get the result
    #result = requests.head(url)

    #if status code is not 200 then print the url (customize the if condition according to the need)
    #if result.status_code != 200:
    #print(url, result.status_code)
   for scriptline in all_scripts:
      scriptvar = scriptline.get_attribute('innerHTML').replace('\"', \" \").replace(')', \" \").replace(';', \" \").replace('\'', \" \").replace('^', \" \").replace('(', \" \").replace('{', \" \").replace('}', \" \").replace('@', \" \").replace('*', \" \").replace('\#', \"\").replace(\"\\r\", \" \").replace(\"\\n\", \" \").replace(\" \", \" \").replace(\"</\", \" \").replace(\"<\", \" \").replace(\">\", \" \").replace(\"?\", \" $1?\")
      if \"/\" in scriptvar:
         allurls = allurls + space + scriptvar
      allrequests = allrequests + spacefiller + scriptvar
      #print(\"\")
      #print(scriptvar)  #filterout querystring & query

   for directurl in all_directurls:
      directurlurl = directurl.get_attribute('url').replace(\"\\r\", \" \").replace(\"\\n\", \" \")
      allurls = allurls + space + directurlurl


   for sourcedoc in all_sourcedocs:
      sourcedocurl = sourcedoc.get_attribute('srcdoc').replace(\"\\r\", \"ö\").replace(\"\\n\", \"ö\")
      allurls = allurls + space + sourcedocurl
      
   bpslen = len(str(browser.page_source))
   fullbps = browser.page_source.replace('\"', \" \").replace(')', \" \").replace(';', \" \").replace('\'', \" \").replace('^', \" \").replace('(', \" \").replace('{', \" \").replace('}', \" \").replace('@', \" \").replace('*', \" \").replace('\#', \"\").replace(\"\\r\", \" \").replace(\"\\n\", \" \").replace(\" \", \" \").replace(\"</\", \" \").replace(\"<\", \" \").replace(\">\", \" \").replace(\"?\", \" $1?\")
   if bpslen > 100000:
      for bpsline in fullbps:
         if \"/\" in bpsline:
            allurls = allurls + spacefiller + bpsline

      ###

   for formlink in all_forms:
      formurl = formlink.get_attribute('action').replace(\"\\r\", \" \").replace(\"\\n\", \" \")
      fullform = formlink.get_attribute('outerHTML').replace(\"\\r\", \"ö\").replace(\"\\n\", \"ö\").replace(\" \", \"ö\")
      allurls = allurls + space + formurl
      allrequests = allrequests + spacefiller + fullform


except:
   print(\"\")

print(allrequests.replace(\"\\r\", \"ö\").replace(\"\\n\", \"ö\").replace(\" \", \"ö\"))
print(\" \")
print(allurls.replace(\"\\r\", \" \").replace(\"\\n\", \" \").replace(\" \", \" \"))
browser.close()
browser.quit()

")
#oefilter="ö"
#spacefilter=" "
for seleniumpart in $seleniumout
do
   if [[ "$seleniumpart" = "ÄÄÄ"* ]]; then #!!!
      seleniumoutrequests="$(echo $seleniumpart | tr 'Ä' '' | tr 'ö' ' ' )"
      echo new seleniumoutrequest: $seleniumoutrequests
      if [[ "$seleniumpart" = *"orm"* ]]; then
         form_pages="$form_pages $seleniumpart"
         # request_builder
      fi
   else
      seleniumouturl=${seleniumpart//\\/\/}
      #seleniumouturls="$seleniumouturls $seleniumouturl"
      seleniumouturls="$seleniumouturls $seleniumouturl"
      echo new seleniumouturl: $seleniumouturl
   fi
done

for unfiltered_request in $seleniumoutrequests
do
   #request=request_builder $unfiltered_request
   request_builder $unfiltered_request
   #echo $request
done
# ${variable//expected/replacement}

#seleniumouturls=${seleniumouturls//\\/\/}
echo "seleniumouturls $seleniumouturls"
#seleniumouturls=${seleniumouturls//$oefilter/$spacefilter}
#echo "seleniumouturls after $seleniumouturls"

for unfiltered_urlline in $seleniumouturls
do
   echo $unfiltered_urlline
   if [[ "$unfiltered_urlline" = *"/"*  ]]; then
      if [[ "$unfiltered_urlline" = "/"  ]] || [[ "$unfiltered_urlline" = "//"  ]]; then
         n=n
      else
         unfiltered_urlline="$(echo $unfiltered_urlline | tr '\' '/' )"
         if [[ "$unfiltered_urlline" = "http"* ]]; then
            unfiltered_urllines="$unfiltered_urllines $unfiltered_urlline"
         elif [[ "$unfiltered_urlline" = ":/"*  ]]; then
            unfiltered_urlline="$(echo $unfiltered_urlline | tr ':' '/' )"
            unfiltered_urllines="$unfiltered_urllines https:$unfiltered_urlline"
         elif [[ "$unfiltered_urlline" = ":"*  ]]; then
            unfiltered_urllines="$unfiltered_urllines https$unfiltered_urlline"
         elif [[ "$unfiltered_urlline" = "//"*  ]]; then
            unfiltered_urllines="$unfiltered_urllines https:$unfiltered_urlline"
         elif [[ "$unfiltered_urlline" = "/"*  ]]; then
            unfiltered_urllines="$unfiltered_urllines $scanurl_until_first_slash$unfiltered_urlline"
         else
            unfiltered_urllines="$unfiltered_urllines $scanurl_until_first_slash/$unfiltered_urlline"
         fi
      fi
   fi
done

# URLs speichern
#for url in $unfiltered_urllines
#do
#   endpoint_already_found=0
#   for endpoint in $endpoints
#   do
#      if [[ "$url" = "$endpoint" ]]; then
#         endpoint_already_found=1
#      fi
#      done
#   if [[ $endpoint_already_found = 0 ]]; then
#      endpoints="$endpoints $url"
#   fi
#done


#
irrelevantresults=-8
commonendpointpath=0
urlstoskip=0
howoftenskipped=0

for url in $unfiltered_urllines
do
      echo $url
      #echo loop $url
 if [[ $urlstoskip -gt 1 ]]; then
    (( urlstoskip-- ))
    echo $urlstoskip
 else
   if [[ $irrelevantresults -lt 3 ]]; then
      #echo $url in here
      if [[ "$url" = *"/" ]]; then
         url=${url%?}
      fi
      url_maindomain="${url/$filter/ö}"
      url_maindomain="$(echo $url_maindomain | cut -d "/" -f1 )"
      url_maindomain="${url_maindomain/ö/$filter}"
      
      ignoreurlforcommons="${url/$filter/ö}"
      ignoreurlforcommons="$(echo $ignoreurlforcommons | rev | cut -d "/" -f2- | rev )"
      ignoreurlforcommons="${ignoreurlforcommons/ö/$filter}"
    if [[ "$irrelevantendpoints" = *" $ignoreurlforcommons "* ]] || [[ "$url" = *"/data:image/svg+xml;base64,"* ]] || [[ "$url" = *"/data:image/png;base64,"* ]] || [[ *"$url_maindomain"* = *"$outofscope"* ]] || [[ "$url" = "https://" ]] || [[ "$url" = "http://" ]] || [[ "$url" = "https:/" ]] || [[ "$url" = "http:/" ]] || [[ "$url" = "https:" ]] || [[ "$url" = "http:" ]] || [[ "$url" = "https" ]] || [[ "$url" = "http" ]] || [[ "$url" = *".png" ]] || [[ "$url" = *".css" ]]; then
       echo $url in here error
    elif [[ "$url" = *"."* ]]; then
      endpoint_already_found=0
      commonendpointpath=0
      #echo $url
      if [[ "$endpoints" = *"$url_maindomain"* ]]; then
         n="url_maindomain already known"
      else
         url_hijacking $url_maindomain $url $1
         endpoints="$endpoints $url_maindomain"
      fi
         
      for endpoint in $endpoints
      do
        if [[ $endpoint_already_found = 0 ]]; then
         compareurlforcommons="${endpoint/$filter/ö}"
         compareurlforcommons="$(echo $compareurlforcommons | rev | cut -d "/" -f2- | rev )"
         compareurlforcommons="${compareurlforcommons/ö/$filter}"
         if [[ "$url" = "$endpoint" ]]; then
            endpoint_already_found=1
         elif [[ "$url_maindomain" = "$compareurlforcommons" ]]; then
            n=n
         elif [[ "$url" = "$compareurlforcommons"* ]]; then
            (( commonendpointpath++ ))
            echo "$compareurlforcommons in $url as $endpoint $commonendpointpath"
         fi
        fi
            #if [[ "$compareurlforcommons" = "$endpoint" ]]; then
            #   endpoint_already_found=1
      done
      if [[ $endpoint_already_found = 0 ]] && [[ $commonendpointpath -lt 4 ]] && [[ "$url" = *"$maintarget"* ]]; then
         #echo Added: $url $commonendpointpath
         endpoints="$endpoints $url"
         irrelevantresults=-10
         if [[ "$endpoints" = *"$compareurlforcommons"* ]]; then
               n=n
         else
            endpoints="$endpoints $compareurlforcommons"
         fi
         echo "Added: $url $commonendpointpath"
      elif [[ $commonendpointpath -gt 3 ]]; then
         (( irrelevantresults++ ))
         compareurlforcommons="${url/$filter/ö}"
         compareurlforcommons="$(echo $compareurlforcommons | rev | cut -d "/" -f2- | rev )"
         compareurlforcommons="${compareurlforcommons/ö/$filter}"
         irrelevantendpoints="$irrelevantendpoints $compareurlforcommons"
      elif [[ $endpoint_already_found = 1 ]]; then
         (( irrelevantresults++ ))
      fi
   fi
  else
     (( howoftenskipped++ ))
     urlstoskip=$((15 * $howoftenskipped))
     irrelevantresults=0

  fi
 fi
done


fi

alreadydeepenumedendpoints="$alreadydeepenumedendpoints $1"
fi
}

# scrape_endpoint: (includes check for common vulnerability indicators)
scrape_endpoint () {
   if [[ $2 = "" ]] || [[ $2 = "none" ]]; then
      curlcookies=""
   else
      for curlcookie in $2
      do
         curlcookie="$(echo $curlcookie | tr 'Ü' ' ')"
         curlcookie="--cookie \"$curlcookie\"" # --cookie "Name=Value"
         curlcookies="$curlcookies $curlcookie"
      done
   fi
   # curl --header "Accept: text/javascript" --header "X-Test: hello" (multiple headers)
   # scrape_endpoint input: scrape_url $1 $2 "Accept:Ütext/javascript X-Test:Ühello"
   if [[ $3 = "" ]] || [[ $3 = "none" ]]; then
      curlheaders=""
   else
      for curlheader in $3
      do
         curlheader="$(echo $curlheader | tr 'Ü' ' ')"
         curlheader="--header \"$curlheader\""
         curlheaders="$curlheaders $curlheader"
      done
   fi
   curlout="$(curl "$1" -i -v $curlcookies $curlheaders)" #-f to hide HTTP errors  ( --user-agent )   -T to upload files! ?
   for vulnerabilityindicatorkeyword in $vulnerabilityindicatorkeywords
   do
      if [[ "$curlout" = *"$vulnerabilityindicatorkeyword"* ]]; then
         interestingcurlout="$vulnerabilityindicatorkeyword: $1 $2 $3"
         interestingcurlout="$(echo $interestingcurlout | tr ' ' 'Ü')"
         interestingrequests="$interestingrequests $interestingcurlout"
      fi
   done
   #gather_endpoint_urls "$curlout"
   # $1 zu schon gescrapten endpoints hinzufügen!
return $curlout
}
# scrape endpoint urls
gather_endpoint_urls () {
   n=n # urls aus curl/$1 auslesen und zu endpoints hunzufügen!
}
# curl to POST data (e.g. a form):
POST_data () {
   n=n
}
# crt.sh scann:
crt_sh_scann () {
   currentcrtshtarget=$1
   subdupe=1
   echo $currentcrtshtarget
   if [[ $includesubdomains = *"yes"* ]]; then
      crtshout="$(timeout 35 curl "https://crt.sh/?q=$currentcrtshtarget")"
      if [[ "$crtshout" = *"</TD>"* ]]; then
      crtshout="$(echo $crtshout | tr '</TD>' ' ' | tr '*' ' ' )"
      for line in $crtshout
      do
         if [[ "$line" = *"$currentcrtshtarget"* ]]; then
            if [[ $line = "."* ]]; then
               cutchar=1
               line="$(echo ${line:$cutchar})"
            fi
            for subdom in $subdoms
            do
               if [[ $subdom = "$line" ]] || [[ "$line" = *"="* ]]; then # or out of scope!
                  subdupe=1
               fi
            done
            if [[ $subdupe = 0 ]]; then
               echo New subdomain: $line
               subdoms="$subdoms $line"
               endpoints="$endpoints https://$line"
               #url_hijacking "https://$line" $line $maintarget
            else
               subdupe=0
            fi
         fi
      done
      else
      crt_sh_scann $currentcrtshtarget
      fi
   else
      subdoms="$subdoms $currentcrtshtarget"
      endpoints="$endpoints https://$currentcrtshtarget"
   fi
}
# Small sub brute:

# XXL sub brute:

# Small dir brute:

# XXL dir brute:
xxl_dir_brute () {
   # Dauerhaft auftauchende responselänge filtern! (ohne --hide-length)
   #   badresponselength="..."
   # use Cookies? --cookies string
   currentxxldirbrutetarget=$1
   badresponselength="0"
   echo $currentxxldirbrutetarget in xxl_dir_brute
   xxldirbruteout="$(gobuster dir -u $currentxxldirbrutetarget -w "$dirtxtxxl" --exclude-length $badresponselength -e --hide-length --wildcard --delay 8000ms --timeout 12s --threads 9 -q -b 400 -b 401 -b 402 -b 403 -b 404 --no-error -a Mozilla)" # -z um progress zu verbergen
   echo gobuster output: $xxldirbruteout #dbg
}
# Custom dir brute:
custom_dir_brute () {
   currentcustomdirbrutetarget=$1
   badresponselength="0"
   echo $currentcustomdirbrutetarget in custom_dir_brute
   customdirbruteout="$(gobuster dir -u $currentcustomdirbrutetarget -w "$customdirstxt" --exclude-length $badresponselength --expanded  --hide-length --wildcard --delay 8000ms --timeout 12s --threads 9 -q -b 400 -b 401 -b 402 -b 403 -b 404 --no-error -a Mozilla)" # -z um progress zu verbergen
   #echo gobuster output: $customdirbruteout #dbg
   for line in $customdirbruteout
   do
      echo $line
   done
   

}

##### Small functions END




#################### Enumeration:
### Basic enum:
basic_enum () {
   crt_sh_scann $maintarget
   # XXL sub brute $maintarget
   for subdom in $subdoms
   do
      echo $subdom
#!!!      #selenium_scrape_endpoint "https://$subdom/robots.txt" #$mainsessioncookie $mainidentifyheader
#!!!      #selenium_scrape_endpoint "https://$subdom/sitemap.xml" #$mainsessioncookie $mainidentifyheader
      #custom_dir_brute "https://$subdom" WICHTIG! noch hinzufügen!
   done
}

### Basic enum END

### Deep Enum:
deep_enum () {
   alreadydeepenumedthisendpoint="0"
   for alreadydeepenumedendpoint in $alreadydeepenumedendpoints
   do
      if [[ "$alreadydeepenumedendpoint" = "$alreadydeepenumedendpoint" ]]; then
         alreadydeepenumedthisendpoint="1"
      fi
   done
   # wenn noch nicht gescannt:
   if [[ $alreadydeepenumedthisendpoint = "0" ]]; then
      curlout="$(scrape_endpoint $1 $2 $3)" # und zu spezifischen endpoints hinzufügen!
      curlout="$(echo $curlout | tr '>' ' ' | tr ';' ' ' | tr '}' ' ' | tr '{' ' ' | tr '"' ' ' | tr ',' ' ' | tr ',' ' ' | sed -r 's/[\]+/ /g')" # urls ausschneiden!
      for line in $curlout
      do
         if [[ $line = *"</"* ]]; then # filtert alle HTML tags
            echo ""
         elif [[ $line = *"$maintarget"* ]] || [[ $line = *"/"* ]]; then # OR /dir OR src="example.com" OR src=example.com OR src="https://example.com" OR /dir
            endpoints="$endpoints $line"
            echo Found new endpoint: $line
            alreadydeepenumedendpoints="$alreadydeepenumedendpoints $line"
         fi
      done
   # URLs auslesen und zu endpoints hinzufügen
   else
      echo Already deepenumed endpoint: "$1"
   fi

}
### request_builder
request_builder () {
   inner_request_builder_var = "lol$1 innen"
   echo $inner_request_builder_var
#return $inner_request_builder_var
}

### Param enum:
# Common XSS & Html Injection params on h1 and in general

#################### Enumeration END



#################### Vulnchecks:
### Subdomain takeover: # mit abspeichern
subdomain_takeover () {
   if [[ DNS_nr = 0 ]]; then
      DNS_IP="1.1.1.1" # cloudflare
      DNS_nr=1
   elif [[ DNS_nr = 1 ]]; then
      DNS_IP="8.8.8.8" # google
      DNS_nr=0
   fi
   digout="$(timeout 12 dig @$DNS_IP $1 CNAME)"
   echo $digout #... Unfinished!
}

### Open Redirect:
# lame ...


### Text Injection: #only on endpoint parameters
interesting_text_injection_findings=""
text_injection () { # not a vulnerability just searving as a potential indicator
   for endpoint in $endpoints
   do
      if [[ "$endpoint" = *"$maintarget"* ]]; then
         if [[ "$endpoint" = *"?" ]]; then
            n=n
         elif [[ "$endpoint" = *"?"* ]]; then
            if [[ "$endpoint" = *"="* ]]; then
               endpoint="$(timeout 12 python3 -c "
endpoint = \"$endpoint\"
endpoint = endpoint.replace(\"=\", \"=%3Cyyy12345\")
print(endpoint)
               ")"
            else #could also add! e.g.: ?param1=val1&param2
               endpoint="$endpoint=%3Cyyy12345"
            fi
            seleniumout="$(timeout 12 python3 -c "
from time import sleep
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
browser = webdriver.Safari()
browser.implicitly_wait(1)
try:
   browser.get(\"$endpoint\")
   #driver.add_cookie({"test1": "key", "value": "value"})
   sleep(1)
   all_text = browser.find_elements(By.TAG_NAME, 'body')
   
   for text in all_text:
      textvar = text.get_attribute('innerText')
      #print(\"\")
      print(textvar)
except:
   print(\"\")
browser.close()
browser.quit()
            ")"
            if [[ "$seleniumout" = *"<yyy12345"* ]]; then
               interesting_text_injection_findings="$interesting_text_injection_findings $endpoint"
               echo ---------------  Interesting finding:  ---------------
               echo Text_Injection: $endpoint
               echo ------------------------------------------------------
            fi
         fi
      fi
   done
}

### HTML Injection:
HTML_injection_findings=""
HTML_injection () {
   for endpoint in $endpoints
   do
      if [[ "$endpoint" = *"$maintarget"* ]]; then
         if [[ "$endpoint" = *"?" ]]; then
            n=n
         elif [[ "$endpoint" = *"?"* ]]; then
            if [[ "$endpoint" = *"="* ]]; then
               endpoint="$(timeout 12 python3 -c "
endpoint = \"$endpoint\"
endpoint = endpoint.replace(\"=\", \"=%3Ca%3Eyyy1%3C%2Fa%3E2345\")
print(endpoint)
               ")"
            else #could also add! e.g.: ?param1=val1&param2
               endpoint="$endpoint=yyy12345"
            fi
            seleniumout="$(timeout 12 python3 -c "
from time import sleep
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
browser = webdriver.Safari()
browser.implicitly_wait(1)
try:
   browser.get(\"$endpoint\")
   #driver.add_cookie({"test1": "key", "value": "value"})
   sleep(1)
   all_text = browser.find_elements(By.TAG_NAME, 'body')
   
   for text in all_text:
      textvar = text.get_attribute('innerText')
      #print(\"\")
      print(textvar)
except:
   print(\"\")
browser.close()
browser.quit()
            ")"
            if [[ "$seleniumout" = *"yyy12345"* ]]; then
               HTML_injection_findings="$HTML_injection_findings $endpoint"
               echo ---------------  Interesting finding:  ---------------
               echo HTML_Injection: $endpoint
               echo ------------------------------------------------------
            fi
         fi
      fi
   done
}
# a tag & iframe tag
# also in emails

### XSS:
# with XSS hunter payloads (obfusicated) ALSO TESTING FORMS (POST-REQUESTS WITH CURL)
# (save information including time and endpoint about every blind iframe payload (this includes cookies and headers)
# Test custom payloads from file
# /dir/asd'...XSS payload (research!)
XSS () {
   echo $1 $2 # $2 = test type e.g. parameter or post request content
}

### Auth bypass:
# by using intranet. or localhost (e.g. on 5.. status codes)
status_code_bypass () { # may not get cached!
echo "bad request for $1"
regular="$(python3 -c "
import requests

headers = {'Accept': '*/*', 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0'}
try:
   r = requests.get('$1', timeout=3, headers=headers)
   print(r.text)
except:
   print(\"\")
   ")"
echo $regular
}
#
auth_bypass () {
   n=n
}
### SSTI:
# blind SSTI

### SQL Injection
# also in url: .../dir/dir/%22

### Header Injection:
# gobuster: --headers stringArray

### Request Smuggeling:

### Cache poisoning:

### Desync attacks:
# Browser powered desync

### URL hijacking
potential_broken_URL_findings=""
url_hijacking () {
#url="$1"
#filter="//"
#url_hijacking_now_maindomain="${url/$filter/ö}"
#url_hijacking_now_maindomain="$(echo $compareurlforcommons | cut -d "/" -f1 )"
#url_hijacking_now_maindomain="${compareurlforcommons/ö/$filter}"
if [[ "$alreadydeepenumedendpoints" = *" $1 "* ]] || [[ "$1" = "https://$maintarget"* ]] || [[ "$1" = "http://$maintarget"* ]] || [[ "$1" = *"google"* ]] || [[ "$1" = *"gstatic"* ]]; then
      n=n #
else
echo "url_hijacking_now - Selenum for $1"
pyrequestsout=$(timeout 12 python3 -c "
from time import sleep
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
browser = webdriver.Safari()
browser.implicitly_wait(1)
try:
   browser.get(\"$1\")
   #driver.add_cookie({"test1": "key", "value": "value"})
   #sleep(0.2)
   all_text = browser.find_elements(By.TAG_NAME, 'body')
   
   for text in all_text:
      textvar = text.get_attribute('innerText')
      #print(\"\")
      print(textvar)
except:
   print(\"\")

try:
   browser.get(\"$2\")
   #driver.add_cookie({"test1": "key", "value": "value"})
   #sleep(0.2)
   all_text = browser.find_elements(By.TAG_NAME, 'body')
   
   for text in all_text:
      textvar = text.get_attribute('innerText')
      #print(\"\")
      print(textvar)
except:
   print(\"\")


browser.close()
browser.quit()
")

echo $pyrequestsout
#alreadydeepenumedendpoints="$alreadydeepenumedendpoints $1"

for keyword in $subtakekeywordstxt
do
   keyword="$(echo $keyword | tr 'ö' ' ' )"
   if [[ "$pyrequestsout" = *"$keyword"* ]]; then
      presentedkeyword="$(echo $keyword | tr ' ' '.' )"
      potential_broken_URL_findings="$potential_broken_URL_findings $1.referenced.as.$2.on.$3.[keyword:.$keyword]"
      echo ===============  Potential finding:  ===============
      echo Broken URL: "$1 referenced as $2 on $3 [keyword: $keyword]"
      echo ====================================================
   fi
done
fi
}

### General interesting behaviour:
# checking saved interesting behaviour from functions


## => Further research (on h1) for further Vulnchecks
#################### Vulnchecks END






############################################# Functions END



############################################# Exec:
basic_enum
selenium_scrape_endpoint "https://$maintarget"
# für jeden Layer:!
   # für jeden endpoint
for endpoint in $endpoints
do
   if [[ "$alreadydeepenumedendpoints" = *" $endpoint "* ]]; then
      echo "$endpoint in alreadydeepenumedendpoints"
   else
      inscope=1
      for scopeout in $outofscope
      do
         if [[ "$endpoint" = *"$scopeout"* ]]; then
            inscope=0
         fi
      done
      if [[ "$endpoint" = *"$maintarget"* ]] && [[ "$inscope" = 1 ]]; then
         selenium_scrape_endpoint $endpoint #$mainsessioncookie #$mainidentifyheader
         alreadydeepenumedendpoints="$alreadydeepenumedendpoints $endpoint"
         echo "$endpoint müsste scrapen"
      else
         echo "$maintarget passt nicht zu $endpoint"
      fi
   fi
done
results

# 2.mal
if [[ "1" = "1" ]]; then
for endpoint in $endpoints
do
   echo $endpoint
   if [[ "$alreadydeepenumedendpoints" = *" $endpoint "* ]]; then
      n=n
   else
      inscope=1
      for scopeout in $outofscope
      do
         if [[ "$endpoint" = *"$scopeout"* ]]; then
            inscope=0
         fi
      done
      if [[ "$endpoint" = *"$maintarget"* ]] && [[ "$inscope" = 1 ]]; then
         selenium_scrape_endpoint $endpoint #$mainsessioncookie #$mainidentifyheader
         alreadydeepenumedendpoints="$alreadydeepenumedendpoints $endpoint"
         echo $endpoints
      fi
   fi
done
fi
#results

# 3.mal
if [[ "1" = "0" ]]; then
for endpoint in $endpoints
do
   echo $endpoint
   if [[ "$alreadydeepenumedendpoints" = *" $endpoint "* ]]; then
      n=n
   else
      inscope=1
      for scopeout in $outofscope
      do
         if [[ "$endpoint" = *"$scopeout"* ]]; then
            inscope=0
         fi
      done
      if [[ "$endpoint" = *"$maintarget"* ]] && [[ "$inscope" = 1 ]]; then
         selenium_scrape_endpoint $endpoint #$mainsessioncookie #$mainidentifyheader
         alreadydeepenumedendpoints="$alreadydeepenumedendpoints $endpoint"
         echo $endpoints
      fi
   fi
done
fi

# Running VulnScanns:
#text_injection
HTML_injection
############################################# Exec END



############################################# Output:
results () {
echo =============== Gathered information ===============
echo Endpoint Enum:
for endpoint in $endpoints
do
   if [[ "$endpoint" = *"$maintarget"* ]]; then
      echo $endpoint
   fi
done
echo Endpoints with forms:
for form_page in $form_pages
do
   echo $form_page
done
echo Endpoints with Login-forms:
echo ---------------  Interesting occurencies  ---------------
echo Text-Injections:
for interesting_text_injection_finding in $interesting_text_injection_findings
do
   echo $interesting_text_injection_finding
done
echo ----------------------------------------------------------
echo ==========================================================================
echo ==========================  Potential findings  ==========================
echo Broken URLs:
for potential_broken_URL_finding in $potential_broken_URL_findings
do
   echo $potential_broken_URL_finding
done
echo - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
echo " "
echo Other vulnerabilitys:
for potential_other_vulnerability in $potential_other_vulnerabilitys
do
   echo $potential_other_vulnerability
done
echo ==========================================================================
}
results
############################################# Output END








#######################################################################################
#
#   Multiprocessing for curl?
#
#
#   BLIND javascript:... XSS IN HOST HEADER ?
#   BLIND HOST HEADER (other blind Injection or RCE) ?
#   message bus & graph ql ?
#   JWT ?
#
#
# Less interesting:
#   (XXE ?)
#   (Automated Google Dorking via Proxy ?)
#
#

