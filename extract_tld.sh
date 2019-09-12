# get all of the ipv4 and ipv6 addresses for every name server for each tld

for zone in `zcat root.zone.gz | awk '$4 == "NS" { print $1 }' | sort -u`; do
  for ns in `dig -q $zone +short ns`; do
    for ip in `dig +short $ns a $ns aaaa`; do
      echo \{\"zone\": \"$zone\", \"ns\": \"$ns\", \"ip\": \"$ip\"\} >> tlds.txt;
    done;
  done;
done
