# get all of the ipv4 and ipv6 addresses for every name server for each domain in the top 5k of alexa sites

for domain in `head -n 5000 alexa-1m-domains.txt | sort -u`; do
  for ns in `dig -q $domain +short ns`; do
    for ip in `dig +short $ns a $ns aaaa`; do
      echo \{\"domain\": \"$domain\", \"ns\": \"$ns\", \"ip\": \"$ip\"\} >> alexa.txt;
    done;
  done;
done