"""The pieces that have to agree with each other so that "push in GitHub Desktop, then install in Unraid" works:
the Unraid template, the GitHub Actions workflow that builds the image, the Dockerfile, the compose file and the app's own environment variables."""
import os, re, xml.etree.ElementTree as ET
import pytest, yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OWNER, REPO = 'xruchai86', 'sarah-companion'
IMAGE = 'ghcr.io/%s/%s' % (OWNER, REPO)


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


def template():
    return ET.parse(os.path.join(ROOT, 'sarah-companion.xml')).getroot()


def workflow():
    return yaml.safe_load(read('.github', 'workflows', 'docker.yml'))


def test_the_template_installs_the_image_that_the_workflow_publishes():
    t = template()
    assert t.findtext('Repository') == IMAGE + ':latest', 'a template that points to an image nobody builds is what made the install fail'
    assert '${GITHUB_REPOSITORY_OWNER,,}/sarah-companion' in read('.github', 'workflows', 'docker.yml'), 'the workflow builds ghcr.io/<owner, lower case>/sarah-companion'
    assert t.findtext('Registry').startswith('https://github.com/%s/%s/pkgs/container/' % (OWNER, REPO))
    assert t.findtext('Project') == 'https://github.com/%s/%s' % (OWNER, REPO)


def test_the_template_urls_are_raw_urls_of_files_that_exist_in_this_repo():
    t = template()
    base = 'https://raw.githubusercontent.com/%s/%s/main/' % (OWNER, REPO)
    for tag in ('TemplateURL', 'Icon'):
        url = t.findtext(tag)
        assert url.startswith(base), tag
        assert os.path.exists(os.path.join(ROOT, url[len(base):])), '%s points to a file that is not in the repository: %s' % (tag, url[len(base):])
    assert t.findtext('TemplateURL')[len(base):] == 'sarah-companion.xml'


def test_every_variable_of_the_template_is_read_by_the_app_and_the_required_ones_are_there():
    t = template()
    variables = {c.get('Target'): c for c in t.findall('Config') if c.get('Type') == 'Variable'}
    src = read('app', 'main.py') + read('app', '__main__.py')
    used = set(re.findall(r"env(?:\.get\(|\[)'([A-Z_]+)'", src)) | {'PORT'}
    used |= set(re.findall(r'environ\.get\("([A-Z_]+)"', read('app', 'tls.py')))
    assert set(variables) <= used, 'the template offers a setting the app ignores: %s' % (set(variables) - used)
    for need in ('OPNSENSE_URL', 'OPNSENSE_KEY', 'OPNSENSE_SECRET', 'UI_PASSWORD'):
        assert variables[need].get('Required') == 'true', need
    for secret in ('OPNSENSE_KEY', 'OPNSENSE_SECRET', 'UI_PASSWORD'):
        assert variables[secret].get('Mask') == 'true', secret + ' must not be shown in clear text'


def test_port_and_data_folder_of_the_template_match_the_dockerfile():
    t = template()
    docker = read('Dockerfile')
    port = [c for c in t.findall('Config') if c.get('Type') == 'Port'][0]
    assert port.get('Target') == re.search(r'ENV .*PORT=(\d+)', docker).group(1) == re.search(r'EXPOSE (\d+)', docker).group(1)
    path = [c for c in t.findall('Config') if c.get('Type') == 'Path'][0]
    assert path.get('Target') == re.search(r'DATA_DIR=(\S+)', docker).group(1)
    assert '--user 99:100' in t.findtext('ExtraParams'), 'Unraid: nobody:users, so that /data is writable'


def test_the_workflow_tests_first_and_only_then_publishes():
    w = workflow()
    assert set(w['jobs']) == {'test', 'image'} and w['jobs']['image']['needs'] == 'test'
    assert w['permissions']['packages'] == 'write'
    on = w.get(True) or w.get('on')                          # YAML turns the key "on" into True
    assert 'main' in on['push']['branches'] and 'pull_request' in on and 'workflow_dispatch' in on
    uses = [s.get('uses', '') for s in w['jobs']['image']['steps']]
    assert any(u.startswith('docker/login-action') for u in uses) and any(u.startswith('docker/build-push-action') for u in uses)
    login = [s for s in w['jobs']['image']['steps'] if s.get('uses', '').startswith('docker/login-action')][0]['with']
    assert login['registry'] == 'ghcr.io' and login['password'] == '${{ secrets.GITHUB_TOKEN }}', 'no personal token needed'
    assert w['jobs']['image']['if'] == "github.event_name != 'pull_request'", 'a pull request builds nothing public'


def test_the_ci_test_job_installs_the_same_pinned_packages_as_the_image():
    steps = ' '.join(s.get('run', '') for s in workflow()['jobs']['test']['steps'])
    assert 'requirements.txt -c constraints.txt' in steps and 'pytest' in steps and 'pyyaml' in steps
    assert 'requirements.txt -c constraints.txt' in read('Dockerfile')


def test_compose_uses_the_published_image():
    c = yaml.safe_load(read('docker-compose.yml'))
    assert c['services']['sarah-companion']['image'] == IMAGE + ':latest'


def test_files_docker_and_the_shell_read_have_unix_line_endings_and_git_keeps_it_that_way():
    for f in ('Dockerfile', 'requirements.txt', 'constraints.txt', 'sarah-companion.xml', os.path.join('.github', 'workflows', 'docker.yml')):
        assert '\r' not in read(f), f + ' has Windows line endings (a trailing backslash in a Dockerfile would break)'
    assert 'eol=lf' in read('.gitattributes')


def test_what_the_image_copies_exists_and_what_it_leaves_out_is_not_needed_to_run():
    docker = read('Dockerfile')
    for f in re.search(r'COPY (requirements.txt constraints.txt) \./', docker).group(1).split():
        assert os.path.exists(os.path.join(ROOT, f))
    assert 'COPY app ./app' in docker
    ign = read('.dockerignore')
    assert 'tests' in ign and not re.search(r'^app', ign, re.M)
    assert 'import tests' not in read('app', 'main.py') + read('app', 'notify.py') + read('app', 'opn.py') + read('app', 'store.py'), 'the app must not need the test folder'
