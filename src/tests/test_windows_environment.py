import json
import pytest
from test_reset import paths,write,platform
from claude_reset.core import build_plan
from claude_reset.discovery import Selection
from claude_reset.catalog import AUTH_VARS
from claude_reset.privacy import flag_states,otel_configuration,vscode_settings
from claude_reset.windows_environment import folded
from claude_reset.safeio import SafetyError,fingerprint


@pytest.mark.parametrize('filename',['settings.json','settings.local.json'])
@pytest.mark.parametrize('spelling',[str.lower,str.title])
def test_every_project_authentication_alias_blocks_without_modifying_or_exporting_values(paths,filename,spelling):
    project=paths.home/'selected-project'
    for name in (*AUTH_VARS,'CLAUDE_CONFIG_DIR','ANTHROPIC_CONFIG_DIR'):
        write(project/'.claude'/filename,json.dumps({'env':{spelling(name):'PRIVATE_FIXTURE_VALUE'}}))
        before=fingerprint(project,project)
        result=build_plan(paths,('code',),selection=Selection(projects=[str(project)]),platform_state=platform(),env={})
        assert any('Project authentication' in b for b in result.blockers),name
        assert 'PRIVATE_FIXTURE_VALUE' not in json.dumps(result.redacted())
        assert fingerprint(project,project)==before


@pytest.mark.parametrize('source',['process','registry'])
def test_windows_authentication_presence_is_case_insensitive(paths,source):
    for name in AUTH_VARS:
        state=platform();env={}
        if source=='process':env[name.lower()]='PRIVATE_FIXTURE_VALUE'
        else:state['environment_presence']={'User:'+name.lower():True}
        result=build_plan(paths,('code',),platform_state=state,env=env)
        assert any('Alternative authentication source' in b for b in result.blockers),name
        assert 'PRIVATE_FIXTURE_VALUE' not in json.dumps(result.redacted())


@pytest.mark.parametrize('source',['process','registry'])
def test_custom_directory_case_does_not_hide_an_unselected_profile(paths,source):
    state=platform();env={};value=str(paths.home/'separate-profile')
    if source=='process':env['claude_config_dir']=value
    else:state['directory_environment']={'claude_config_dir':value}
    result=build_plan(paths,('code',),platform_state=state,env=env)
    assert any('Custom data directory requires explicit' in b for b in result.blockers)


@pytest.mark.parametrize('value',[{'name':'a','NAME':'b'},{1:'PRIVATE_FIXTURE_VALUE'},[]])
def test_ambiguous_or_malformed_names_fail_without_echoing_values(value):
    with pytest.raises(SafetyError) as error:folded(value)
    assert 'PRIVATE_FIXTURE_VALUE' not in str(error.value)


def test_project_case_collision_has_no_applicable_plan(paths):
    project=paths.home/'selected-project'
    write(project/'.claude/settings.json',json.dumps({'env':{'ANTHROPIC_API_KEY':'A','anthropic_api_key':'B'}}))
    result=build_plan(paths,('code',),selection=Selection(projects=[str(project)]),platform_state=platform(),env={})
    assert result.blockers==['Profile discovery failed; no safe plan can be built'] and not result.actions


def test_privacy_names_are_folded_but_values_and_effective_policy_remain_private(paths):
    assert flag_states({'disable_error_reporting':'PRIVATE_FIXTURE_VALUE'})['DISABLE_ERROR_REPORTING']=='set_nonempty'
    value=otel_configuration({'otel_exporter_otlp_headers':'PRIVATE_FIXTURE_VALUE','otel_private_fixture':'PRIVATE_FIXTURE_VALUE'})
    assert value['configuration_present'] and value['other_otel_variable_count']==1
    assert value['known_variable_states']['OTEL_EXPORTER_OTLP_HEADERS']=='set_nonempty'
    assert value['transmission']==value['exporter_enabled']=='not_verified'
    assert 'PRIVATE_FIXTURE_VALUE' not in json.dumps(value)
    root=paths.roaming/'Code/User'
    write(root/'settings.json',json.dumps({'claudeCode.environmentVariables':[
        {'name':'otel_exporter_otlp_headers','value':'PRIVATE_FIXTURE_VALUE'},
        {'name':'disable_error_reporting','value':'PRIVATE_FIXTURE_VALUE'}]}))
    result=vscode_settings(root)
    assert result['opentelemetry']['configuration_present']
    assert result['extension_environment']['DISABLE_ERROR_REPORTING']=='set_nonempty'
    assert 'PRIVATE_FIXTURE_VALUE' not in json.dumps(result)
    write(root/'settings.json',json.dumps({'claudeCode.environmentVariables':[
        {'name':'otel_exporter_otlp_headers','value':'A'},{'name':'OTEL_EXPORTER_OTLP_HEADERS','value':'B'}]}))
    with pytest.raises(SafetyError):vscode_settings(root)
