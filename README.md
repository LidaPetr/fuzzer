This software is testing an application for *SQL injections* and *XSS attacks*.

The software is contained in a python file and it can be executed on any machine that has Python installed as follows:
`python fuzzer.py`

In the same folder, two files need to be included: `sql_payloads.txt` and `xss_payloads.txt` (the first one should contain the static sql payloads, while the second one should contain the static xss payloads). A sample of such files is provided, but you are able to use your own payloads, if they are named as mentioned and they are saved in the working folder. 
 
The url of the website that you want to test can be changed from line 17:
`self.app_root_url = "url_of_website"`

The login parameters should be added in the variable: `self.login_endpoint` (line 20)
The variable `self.endpoints` contains the endpoints that we are testing. You can change them to test different endpoints.
Some sample endpoints are contained in our code. If endpoints are added, the same structure should be used.
(If we want to add an endpoint that it is going to be tested for XSS attacks the `"_method":"patch"` should be added to the `"param_data"`).
In order for the software to be completed faster, not all the payloads provided are used. However, if we increase the number that is contained in the lines 89, 110, 150, 170 (`"for payload in random.sample(payloads, 10):"`), we can test more payloads. Alternatively, we can use "`for payload in payloads:`" instead of "`for payload in random.sample(payloads, 20):`" to use all the static payloads provided.

The results are printed in the console using the following format:
For each endpoint, its url and the tested parameter is printed. Then the type of the attack is shown (static SQL, mutated SQL, static XSS, mutated XSS). Finally the possible attacks alongside with the used payloads are shown to the user. If the software cannot find any possible attack for a specific parameter, `"No possible attack found."` is printed.

An example of an output of one endpoint is presented below:
```
~~~~~~~~NEW ENDPOINT~~~~~~~~
-Url: /sign_in
-Parameter checked: login
SQLi testing using mutated payloads:
POSSIBLE SQL INJECTION with payload: login : admin') or ('1'='1'#
POSSIBLE SQL INJECTION with payload: login : admi#Yn'o") or ("#1"="1E}"-(-
POSSIBLE SQL INJECTION with payload: login : a[@>dAmin"+/'*
POSSIBLE SQL INJECTION with payload: login : admin' or 1=1/*
POSSIBLE SQL INJECTION with payload: login : admin') or '1'='1'/*
POSSIBLE SQL INJECTION with payload: login : admin' or '1'='1'/*
POSSIBLE SQL INJECTION with payload: login : admin' or 1=1

-Parameter checked: password
SQLi testing using static payloads:
No possible attack found.
```

** References **
1. http://www.lifeoverpentest.com/2018/03/sql-injection-login-bypass-cheat-sheet.html?fbclid=IwAR3IH9U21W5Lv3cxEKkqtHr0LdWETD6daZUs2w4zaYJu6yjkYMl9micxJxQ
2. https://gist.github.com/JohannesHoppe/5612274
