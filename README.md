# certbot-namesilo-hook

## What's this for?
For those who use Letsencrypt's [Certbot](https://certbot.eff.org) and want wildcard certificates on Namesilo, certificate creation and renewal is quite a pain since the main method is via the DNS records ACME TXT challenge. Namesilo offers no tooling to assist in automation of the letsencrypt renewal. But it does, however, have an [API we can call](https://www.namesilo.com/api-reference#dns/dns-add-record). We use certbot's [manual-auth-hook](https://certbot.eff.org/docs/using.html#pre-and-post-validation-hooks) to perform our needed function (updating the TXT record and waiting until it is updated), and no longer have to do this manually.

### Requirements
Node.JS, NPM

## How to use?

1. ````npm install -g certbot-namesilo-hook````
2. Generate NameSilo API key (at https://www.namesilo.com/account/api-manager)
3. In your terminal (or in your terminal profile (e.g. .bash_profile/.zprofile) ) do ````export NAMESILO_API="<your_api_key>"```` (add environment variable)
4. When you run certbot, add the options for ````--manual-auth-hook```` and ````--manual-cleanup-hook```` to be certbot-namesilo-hook

#### Example Usage
````
certbot certonly --manual --email awesomeemail@wow.com \
--agree-tos \
--manual-public-ip-logging-ok \
--preferred-challenges=dns \
--manual-auth-hook certbot-namesilo-hook \
--manual-cleanup-hook certbot-namesilo-hook \
-d *.awesomewebsite.com -d awesomewebsite.com
````
Or when renewing
````
certbot renew --email awesomeemail@wow.com \
--agree-tos \
--manual-public-ip-logging-ok \
--preferred-challenges=dns \
--manual-auth-hook certbot-namesilo-hook \
--manual-cleanup-hook certbot-namesilo-hook \
-d *.awesomewebsite.com -d awesomewebsite.com
````



---
##### Tip Jar

<img src="https://upload.wikimedia.org/wikipedia/commons/5/56/Stellar_Symbol.png" alt="Stellar" height="32"/>

```
Stellar Lumens (XLM) : 
GCVKPZQUDXWVNPIIMF3FXR6KWAOHTEWPZZM2AQE4J3TXR6ZDHXQHP5BQ
```

<img src="https://upload.wikimedia.org/wikipedia/commons/1/19/Coin-ada-big.svg" alt="Cardano" height="32">

```
Cardano (ADA) : 
addr1q9datt8urnyuc2059tquh59sva0pja7jqg4nfhnje7xcy6zpndeesglqkxhjvcgdu820flcecjzunwp6qen4yr92gm6smssug8
```
