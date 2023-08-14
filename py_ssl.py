import ssl, socket
from datetime import date
from dateutil import parser
from prettytable import PrettyTable

domains = ["<--domains here-->"]
alt_domains = []
crts = []

class Certificate: 
    def __init__(self, name, san, expire, days_left, common_name):
        self.name = name
        self.san = san
        self.expire = expire
        self.days_left = days_left
        self.common_name = common_name


def main():
    for domain in domains:  
        
        ctx = ssl.create_default_context()

        
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as soc:
            soc.connect((domain, 443))

            cert = soc.getpeercert()
            certificate_domains = dict(x[0] for x in cert['subject'])
            issued_to = certificate_domains['commonName']
            certificate_alt_domain = cert['subjectAltName']

            x = []
            for alt_domain in certificate_alt_domain: 
                alt_domain_lower = alt_domain[1]
                x.append(alt_domain_lower)
                
            res = parser.parse(cert['notAfter'], fuzzy=True)

            current_date = date.today()
            days_left=(res.date()-current_date).days

            crt = Certificate(domain, x, res.date(), days_left, issued_to)
            crts.append(crt)
    
    for crt in crts:
        t = PrettyTable(['Name', 'Common Name', 'Expiration', 'Days Left'])
        t.add_row([crt.name, crt.common_name, crt.expire, crt.days_left])

        x = crt.san
        t_s = PrettyTable(['SANs'])
        for d in x:
            t_s.add_row([d])
        
        print(t)
        print(t_s)
    
if __name__ == "__main__":
    main()