import ipinfo
access_token = 'f805893e85f4ea'
handler = ipinfo.getHandler(access_token)
ip_address = '216.239.36.21'
details = handler.getDetails(ip_address)
details.city
details.loc
