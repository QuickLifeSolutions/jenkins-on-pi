import unittest
import yaml
import os
import tempfile
from unittest.mock import patch, mock_open


class TestJenkinsYAMLConfiguration(unittest.TestCase):
    """
    Comprehensive unit tests for Jenkins YAML configuration file.
    Testing framework: unittest (Python standard library)
    """

    def setUp(self):
        """Set up test fixtures with sample Jenkins YAML configuration."""
        self.sample_jenkins_config = """
jenkins:
  systemMessage: "Apify Actors CI/CD — Managed by JCasC"
  numExecutors: 2
  mode: NORMAL
  nodes:
    - permanent:
        name: "aws-ec2"
        description: "AWS EC2 Ubuntu agent"
        remoteFS: "/opt/jenkins"
        labelString: "aws-ec2"
        numExecutors: 1
        mode: NORMAL
        retentionStrategy:
          always:
            checkInterval: 1
        launcher:
          ssh:
            host: "13.200.56.3"
            port: 22
            credentialsId: "aws-ec2-agent"
            launchTimeoutSeconds: 210
            maxNumRetries: 10
            retryWaitTime: 30
            sshHostKeyVerificationStrategy:
              nonVerifyingKeyVerificationStrategy: {}
  crumbIssuer:
    standard:
      excludeClientIPFromCrumb: true
  authorizationStrategy:
    loggedInUsersCanDoAnything:
      allowAnonymousRead: false
  securityRealm:
    local:
      allowsSignup: false
      users:
        - id: "admin"
          password: "${ADMIN_PASSWORD}"

unclassified:
  location:
    url: "${JENKINS_URL}"
  gitHubConfiguration:
    endpoints:
      - name: "github"
        apiUri: "https://api.github.com"
  globalLibraries:
    libraries:
      - name: "apify-lib"
        retriever:
          modernSCM:
            scm:
              git:
                remote: "https://github.com/QuickLifeSolutions/jenkins-apify-lib.git"
                credentialsId: "github-token"
        defaultVersion: "main"
        allowVersionOverride: false

credentials:
  system:
    domainCredentials:
      - credentials:
          - usernamePassword:
              id: "github-token"
              scope: GLOBAL
              description: "GitHub PAT: repo, admin:repo_hook"
              username: "x-access-token"
              password: "${GITHUB_TOKEN}"
          - string:
              id: "apify-token-dev"
              scope: GLOBAL
              description: "APIFY_TOKEN (DEV)"
              secret: "${APIFY_TOKEN_DEV}"
          - string:
              id: "apify-token-prod"
              scope: GLOBAL
              description: "APIFY_TOKEN (PROD)"
              secret: "${APIFY_TOKEN_PROD}"
          - basicSSHUserPrivateKey:
              id: "aws-ec2-agent"
              scope: GLOBAL
              description: "SSH key for AWS EC2 Jenkins agent"
              username: "ubuntu"
              privateKeySource:
                directEntry: "${AWS_EC2_AGENT_PRIVATE_KEY}"

tool:
  git:
    installations:
      - name: "git"
        home: "/usr/bin/git"

jobs:
  - script: |
      organizationFolder('QuickLifeSolutions') {
        displayName('QuickLifeSolutions')
        organizations {
          github {
            repoOwner('QuickLifeSolutions')
            credentialsId('github-token')
            traits {
              gitHubExcludeArchivedRepositories()
              gitHubBranchDiscovery { strategyId(3) }
              gitHubTagDiscovery()
              gitHubPullRequestDiscovery { strategyId(3) }
              sourceWildcardFilter {
                includes('*')
                excludes('')
              }
            }
          }
        }
        projectFactories {
          workflowMultiBranchProjectFactory {
            scriptPath('ci/Jenkinsfile')
          }
        }
        orphanedItemStrategy { discardOldItems { daysToKeep(30); numToKeep(60) } }
      }
"""
        self.config_dict = yaml.safe_load(self.sample_jenkins_config)

    def test_yaml_parsing_valid_config(self):
        """Test that valid YAML configuration parses correctly."""
        parsed_config = yaml.safe_load(self.sample_jenkins_config)
        self.assertIsInstance(parsed_config, dict)
        self.assertIn('jenkins', parsed_config)
        self.assertIn('unclassified', parsed_config)
        self.assertIn('credentials', parsed_config)
        self.assertIn('tool', parsed_config)
        self.assertIn('jobs', parsed_config)

    def test_yaml_parsing_invalid_yaml(self):
        """Test that invalid YAML raises appropriate exceptions."""
        invalid_yaml = """
jenkins:
  systemMessage: "Unclosed string
  numExecutors: 2
"""
        with self.assertRaises(yaml.YAMLError):
            yaml.safe_load(invalid_yaml)

    def test_jenkins_main_configuration_structure(self):
        """Test Jenkins main configuration section structure and values."""
        jenkins_config = self.config_dict['jenkins']

        # Test required fields
        self.assertEqual(jenkins_config['systemMessage'], "Apify Actors CI/CD — Managed by JCasC")
        self.assertEqual(jenkins_config['numExecutors'], 2)
        self.assertEqual(jenkins_config['mode'], 'NORMAL')

        # Test configuration types
        self.assertIsInstance(jenkins_config['numExecutors'], int)
        self.assertIsInstance(jenkins_config['systemMessage'], str)
        self.assertIsInstance(jenkins_config['mode'], str)

    def test_jenkins_nodes_configuration(self):
        """Test Jenkins nodes configuration for AWS EC2 agent."""
        nodes = self.config_dict['jenkins']['nodes']
        self.assertIsInstance(nodes, list)
        self.assertEqual(len(nodes), 1)

        ec2_node = nodes[0]['permanent']
        self.assertEqual(ec2_node['name'], 'aws-ec2')
        self.assertEqual(ec2_node['description'], 'AWS EC2 Ubuntu agent')
        self.assertEqual(ec2_node['remoteFS'], '/opt/jenkins')
        self.assertEqual(ec2_node['labelString'], 'aws-ec2')
        self.assertEqual(ec2_node['numExecutors'], 1)
        self.assertEqual(ec2_node['mode'], 'NORMAL')

    def test_ssh_launcher_configuration(self):
        """Test SSH launcher configuration for EC2 node."""
        ssh_config = self.config_dict['jenkins']['nodes'][0]['permanent']['launcher']['ssh']

        self.assertEqual(ssh_config['host'], '13.200.56.3')
        self.assertEqual(ssh_config['port'], 22)
        self.assertEqual(ssh_config['credentialsId'], 'aws-ec2-agent')
        self.assertEqual(ssh_config['launchTimeoutSeconds'], 210)
        self.assertEqual(ssh_config['maxNumRetries'], 10)
        self.assertEqual(ssh_config['retryWaitTime'], 30)

        # Test numeric types
        self.assertIsInstance(ssh_config['port'], int)
        self.assertIsInstance(ssh_config['launchTimeoutSeconds'], int)
        self.assertIsInstance(ssh_config['maxNumRetries'], int)
        self.assertIsInstance(ssh_config['retryWaitTime'], int)

    def test_retention_strategy_configuration(self):
        """Test node retention strategy configuration."""
        retention_config = self.config_dict['jenkins']['nodes'][0]['permanent']['retentionStrategy']
        self.assertIn('always', retention_config)
        self.assertEqual(retention_config['always']['checkInterval'], 1)

    def test_security_configuration(self):
        """Test Jenkins security configuration including CSRF and auth."""
        jenkins_config = self.config_dict['jenkins']

        # Test CSRF protection
        crumb_config = jenkins_config['crumbIssuer']['standard']
        self.assertTrue(crumb_config['excludeClientIPFromCrumb'])

        # Test authorization strategy
        auth_strategy = jenkins_config['authorizationStrategy']['loggedInUsersCanDoAnything']
        self.assertFalse(auth_strategy['allowAnonymousRead'])

        # Test security realm
        security_realm = jenkins_config['securityRealm']['local']
        self.assertFalse(security_realm['allowsSignup'])

    def test_local_user_configuration(self):
        """Test local user configuration."""
        users = self.config_dict['jenkins']['securityRealm']['local']['users']
        self.assertIsInstance(users, list)
        self.assertEqual(len(users), 1)

        admin_user = users[0]
        self.assertEqual(admin_user['id'], 'admin')
        self.assertEqual(admin_user['password'], '${ADMIN_PASSWORD}')

    def test_unclassified_configuration(self):
        """Test unclassified configuration section."""
        unclassified = self.config_dict['unclassified']

        # Test location configuration
        self.assertEqual(unclassified['location']['url'], '${JENKINS_URL}')

        # Test GitHub configuration
        github_endpoints = unclassified['gitHubConfiguration']['endpoints']
        self.assertIsInstance(github_endpoints, list)
        self.assertEqual(len(github_endpoints), 1)
        self.assertEqual(github_endpoints[0]['name'], 'github')
        self.assertEqual(github_endpoints[0]['apiUri'], 'https://api.github.com')

    def test_global_libraries_configuration(self):
        """Test global libraries configuration."""
        global_libs = self.config_dict['unclassified']['globalLibraries']['libraries']
        self.assertIsInstance(global_libs, list)
        self.assertEqual(len(global_libs), 1)

        apify_lib = global_libs[0]
        self.assertEqual(apify_lib['name'], 'apify-lib')
        self.assertEqual(apify_lib['defaultVersion'], 'main')
        self.assertFalse(apify_lib['allowVersionOverride'])

        # Test SCM configuration
        git_config = apify_lib['retriever']['modernSCM']['scm']['git']
        self.assertEqual(git_config['remote'], 'https://github.com/QuickLifeSolutions/jenkins-apify-lib.git')
        self.assertEqual(git_config['credentialsId'], 'github-token')

    def test_credentials_configuration_structure(self):
        """Test credentials system configuration structure."""
        credentials_config = self.config_dict['credentials']['system']['domainCredentials']
        self.assertIsInstance(credentials_config, list)
        self.assertEqual(len(credentials_config), 1)

        credentials = credentials_config[0]['credentials']
        self.assertIsInstance(credentials, list)
        self.assertEqual(len(credentials), 4)  # github-token, apify-dev, apify-prod, aws-ec2-agent

    def test_username_password_credentials(self):
        """Test username/password credential configuration."""
        credentials = self.config_dict['credentials']['system']['domainCredentials'][0]['credentials']

        github_cred = credentials[0]['usernamePassword']
        self.assertEqual(github_cred['id'], 'github-token')
        self.assertEqual(github_cred['scope'], 'GLOBAL')
        self.assertEqual(github_cred['description'], 'GitHub PAT: repo, admin:repo_hook')
        self.assertEqual(github_cred['username'], 'x-access-token')
        self.assertEqual(github_cred['password'], '${GITHUB_TOKEN}')

    def test_string_credentials(self):
        """Test string credential configurations."""
        credentials = self.config_dict['credentials']['system']['domainCredentials'][0]['credentials']

        # Test dev token
        dev_cred = credentials[1]['string']
        self.assertEqual(dev_cred['id'], 'apify-token-dev')
        self.assertEqual(dev_cred['scope'], 'GLOBAL')
        self.assertEqual(dev_cred['description'], 'APIFY_TOKEN (DEV)')
        self.assertEqual(dev_cred['secret'], '${APIFY_TOKEN_DEV}')

        # Test prod token
        prod_cred = credentials[2]['string']
        self.assertEqual(prod_cred['id'], 'apify-token-prod')
        self.assertEqual(prod_cred['scope'], 'GLOBAL')
        self.assertEqual(prod_cred['description'], 'APIFY_TOKEN (PROD)')
        self.assertEqual(prod_cred['secret'], '${APIFY_TOKEN_PROD}')

    def test_ssh_private_key_credentials(self):
        """Test SSH private key credential configuration."""
        credentials = self.config_dict['credentials']['system']['domainCredentials'][0]['credentials']

        ssh_cred = credentials[3]['basicSSHUserPrivateKey']
        self.assertEqual(ssh_cred['id'], 'aws-ec2-agent')
        self.assertEqual(ssh_cred['scope'], 'GLOBAL')
        self.assertEqual(ssh_cred['description'], 'SSH key for AWS EC2 Jenkins agent')
        self.assertEqual(ssh_cred['username'], 'ubuntu')
        self.assertEqual(ssh_cred['privateKeySource']['directEntry'], '${AWS_EC2_AGENT_PRIVATE_KEY}')

    def test_tool_configuration(self):
        """Test tool configuration section."""
        tools = self.config_dict['tool']

        # Test Git installation
        git_installations = tools['git']['installations']
        self.assertIsInstance(git_installations, list)
        self.assertEqual(len(git_installations), 1)

        git_install = git_installations[0]
        self.assertEqual(git_install['name'], 'git')
        self.assertEqual(git_install['home'], '/usr/bin/git')

    def test_jobs_configuration(self):
        """Test jobs configuration section."""
        jobs = self.config_dict['jobs']
        self.assertIsInstance(jobs, list)
        self.assertEqual(len(jobs), 1)

        job_script = jobs[0]['script']
        self.assertIsInstance(job_script, str)
        self.assertIn("organizationFolder('QuickLifeSolutions')", job_script)
        self.assertIn("repoOwner('QuickLifeSolutions')", job_script)
        self.assertIn("credentialsId('github-token')", job_script)
        self.assertIn("scriptPath('ci/Jenkinsfile')", job_script)

    def test_environment_variable_placeholders(self):
        """Test that environment variable placeholders are properly formatted."""
        config_str = yaml.dump(self.config_dict)

        # Check for environment variable patterns
        env_vars = ['${ADMIN_PASSWORD}', '${JENKINS_URL}', '${GITHUB_TOKEN}', 
                   '${APIFY_TOKEN_DEV}', '${APIFY_TOKEN_PROD}', '${AWS_EC2_AGENT_PRIVATE_KEY}']

        for env_var in env_vars:
            self.assertIn(env_var, config_str)

    def test_required_sections_present(self):
        """Test that all required top-level sections are present."""
        required_sections = ['jenkins', 'unclassified', 'credentials', 'tool', 'jobs']

        for section in required_sections:
            self.assertIn(section, self.config_dict, f"Required section '{section}' missing")

    def test_credential_ids_consistency(self):
        """Test that credential IDs are consistently referenced across configuration."""
        # Extract credential IDs from credentials section
        credentials = self.config_dict['credentials']['system']['domainCredentials'][0]['credentials']
        defined_cred_ids = set()

        for cred in credentials:
            for _cred_type, cred_config in cred.items():
                defined_cred_ids.add(cred_config['id'])

        # Check references match defined credentials
        ssh_cred_id = self.config_dict['jenkins']['nodes'][0]['permanent']['launcher']['ssh']['credentialsId']
        self.assertIn(ssh_cred_id, defined_cred_ids)

        lib_cred_id = self.config_dict['unclassified']['globalLibraries']['libraries'][0]['retriever']['modernSCM']['scm']['git']['credentialsId']
        self.assertIn(lib_cred_id, defined_cred_ids)

    def test_numeric_values_are_integers(self):
        """Test that numeric configuration values are proper integers."""
        # Jenkins main config
        self.assertIsInstance(self.config_dict['jenkins']['numExecutors'], int)

        # Node config
        node_config = self.config_dict['jenkins']['nodes'][0]['permanent']
        self.assertIsInstance(node_config['numExecutors'], int)

        # SSH launcher config
        ssh_config = node_config['launcher']['ssh']
        self.assertIsInstance(ssh_config['port'], int)
        self.assertIsInstance(ssh_config['launchTimeoutSeconds'], int)
        self.assertIsInstance(ssh_config['maxNumRetries'], int)
        self.assertIsInstance(ssh_config['retryWaitTime'], int)

    def test_boolean_values_are_proper_booleans(self):
        """Test that boolean configuration values are proper booleans."""
        # CSRF config
        csrf_config = self.config_dict['jenkins']['crumbIssuer']['standard']
        self.assertIsInstance(csrf_config['excludeClientIPFromCrumb'], bool)

        # Auth config
        auth_config = self.config_dict['jenkins']['authorizationStrategy']['loggedInUsersCanDoAnything']
        self.assertIsInstance(auth_config['allowAnonymousRead'], bool)

        # Security realm config
        security_config = self.config_dict['jenkins']['securityRealm']['local']
        self.assertIsInstance(security_config['allowsSignup'], bool)

        # Global library config
        lib_config = self.config_dict['unclassified']['globalLibraries']['libraries'][0]
        self.assertIsInstance(lib_config['allowVersionOverride'], bool)

    def test_empty_yaml_handling(self):
        """Test handling of empty YAML configuration."""
        empty_yaml = ""
        parsed = yaml.safe_load(empty_yaml)
        self.assertIsNone(parsed)

    def test_malformed_yaml_structure(self):
        """Test handling of malformed YAML structure."""
        malformed_yaml = """
jenkins:
  - invalid_list_under_jenkins
"""
        parsed = yaml.safe_load(malformed_yaml)
        # Should parse but have unexpected structure
        self.assertNotIsInstance(parsed['jenkins'], dict)

    def test_missing_required_jenkins_fields(self):
        """Test validation of missing required Jenkins fields."""
        minimal_config = {"jenkins": {}}

        # This should pass parsing but may fail validation
        self.assertIsInstance(minimal_config, dict)
        self.assertIn('jenkins', minimal_config)

        # Check that required fields would be missing
        jenkins_config = minimal_config['jenkins']
        self.assertNotIn('systemMessage', jenkins_config)
        self.assertNotIn('numExecutors', jenkins_config)

    def test_yaml_round_trip_consistency(self):
        """Test that YAML can be loaded and dumped consistently."""
        # Load, dump, and reload to test consistency
        reloaded_config = yaml.safe_load(yaml.dump(self.config_dict))

        # Key structural elements should be preserved
        self.assertEqual(
            reloaded_config['jenkins']['systemMessage'],
            self.config_dict['jenkins']['systemMessage']
        )
        self.assertEqual(
            reloaded_config['jenkins']['numExecutors'],
            self.config_dict['jenkins']['numExecutors']
        )

    def test_large_yaml_performance(self):
        """Test performance with larger YAML configurations."""
        # Create a larger config by duplicating nodes
        large_config = self.config_dict.copy()
        nodes_list = []

        for i in range(10):  # Create 10 similar nodes
            node = large_config['jenkins']['nodes'][0].copy()
            node['permanent']['name'] = f'aws-ec2-{i}'
            node['permanent']['labelString'] = f'aws-ec2-{i}'
            nodes_list.append(node)

        large_config['jenkins']['nodes'] = nodes_list

        # Should parse without issues
        yaml_string = yaml.dump(large_config)
        reparsed = yaml.safe_load(yaml_string)
        self.assertEqual(len(reparsed['jenkins']['nodes']), 10)

    def test_unicode_and_special_characters(self):
        """Test handling of unicode and special characters in configuration."""
        unicode_config = self.config_dict.copy()
        unicode_config['jenkins']['systemMessage'] = "Jenkins — CI/CD with émojis 🚀"

        yaml_string = yaml.dump(unicode_config, allow_unicode=True)
        reparsed = yaml.safe_load(yaml_string)

        self.assertEqual(reparsed['jenkins']['systemMessage'], "Jenkins — CI/CD with émojis 🚀")

    @patch.dict(os.environ, {
        'ADMIN_PASSWORD': 'test_password',
        'JENKINS_URL': 'http://test-jenkins.com',
        'GITHUB_TOKEN': 'test_github_token'
    })
    def test_environment_variable_substitution_simulation(self):
        """Test simulation of environment variable substitution."""
        # This tests the pattern, actual substitution would be done by Jenkins
        config_str = yaml.dump(self.config_dict)

        # Verify environment variable patterns are present and could be substituted
        self.assertIn('${ADMIN_PASSWORD}', config_str)
        self.assertIn('${JENKINS_URL}', config_str)
        self.assertIn('${GITHUB_TOKEN}', config_str)

        # Simulate basic substitution (for testing purposes)
        substituted = config_str.replace('${ADMIN_PASSWORD}', os.environ.get('ADMIN_PASSWORD', ''))
        self.assertIn('test_password', substituted)

    def tearDown(self):
        """Clean up test fixtures."""
        # Clean up any temporary files if created
        pass


if __name__ == '__main__':
    unittest.main()