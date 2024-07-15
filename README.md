# jenkins-decryptor

Install with [pipx](https://github.com/pypa/pipx).

~~~ bash
pipx install git+https://github.com/dadevel/jenkins-decryptor.git@main
~~~

Exfiltrate following files from Jenkins:

~~~
secrets/master.key
secrets/hudson.util.Secret
credentials.xml
jobs/**/build.xml
jobs/**/config.xml
~~~

Decrypt secrets offline.

~~~ bash
jenkins-decyptor ./master.key ./hudson.util.Secret ./credentials.xml ./jobs/**/*.xml
~~~

References:

- [github.com/gquere/pwn_jenkins](https://github.com/gquere/pwn_jenkins)
