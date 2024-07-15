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

For example by creating a new *Pipeline* project with a *Pipeline script* based on this [Jenkinsfile](./extras/Jenkinsfile).
Then you can retrieve the files from the *Console output*.

Decrypt secrets offline.

~~~ bash
jenkins-decyptor ./master.key ./hudson.util.Secret ./credentials.xml ./jobs/**/*.xml
~~~

In some cases file credentials (*FileCredentialsImpl* in XML) are not decrypted correctly.
See this [Jenkinsfile](./extras/Jenkinsfile) for how to retrieve them online.

References:

- [github.com/gquere/pwn_jenkins](https://github.com/gquere/pwn_jenkins)
