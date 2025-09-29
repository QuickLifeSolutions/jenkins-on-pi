import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.plugins.credentials.impl.*
import jenkins.model.Jenkins

final String credentialId = "aws-ec2-agent"
final File keyFile = new File("/var/jenkins_home/external-keys/jenkins-agent")

if (!keyFile.exists()) {
    println "[init] EC2 key file not found at ${keyFile.absolutePath}; skipping credential provisioning"
    return
}

def privateKey = keyFile.getText("UTF-8")
if (!privateKey?.trim()) {
    println "[init] EC2 key file empty at ${keyFile.absolutePath}; skipping credential provisioning"
    return
}

def store = SystemCredentialsProvider.getInstance().getStore()
def domain = Domain.global()

def existing = store.getCredentials(domain).find { it.id == credentialId }
if (existing != null) {
    store.removeCredentials(domain, existing)
    println "[init] Removed existing credential '${credentialId}'"
}

def credential = new BasicSSHUserPrivateKey(
        CredentialsScope.GLOBAL,
        credentialId,
        "ubuntu",
        new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(privateKey),
        "",
        "SSH key for AWS EC2 Jenkins agent"
)

store.addCredentials(domain, credential)
println "[init] Provisioned credential '${credentialId}' from ${keyFile.absolutePath}"
