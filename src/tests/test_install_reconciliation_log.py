"""Durable attempt history tests using real temporary files, no SCM writes."""
from contextlib import contextmanager
import pytest
from claude_reset.install_reconciliation_log import ReconciliationLog
from claude_reset.install_service_receipts import ServiceReceipts
from claude_reset.install_journal import _LocalFile
from claude_reset.install_scm import SERVICES,specification
from claude_reset.safeio import SafetyError
from test_install_service_receipts import initial


@contextmanager
def setup(tmp_path):
    with _LocalFile(tmp_path) as journal:
        tx=initial();journal.save(tx);source=ServiceReceipts(journal);source.begin()
        for name in SERVICES:
            source.record('intent',specification(name));source.record('disabled',specification(name))
        tx['state']='recovering';journal.save(tx)
        yield ReconciliationLog(journal)


def test_new_attempt_preserves_unknown_prior_result_without_rewriting_it(tmp_path):
    with setup(tmp_path) as log:
        first=log.begin(['SbieDrv']);log.record(first,'delete_intent',specification('SbieSvc'))
        original=log.load()['attempts'][0]
        second=log.begin(['SbieSvc','SbieDrv'])
        with pytest.raises(SafetyError):log.record(first,'delete_requested',specification('SbieSvc'))
        for name in ('ClaudeResetGateway','ClaudeResetBackend'):
            log.record(second,'delete_intent',specification(name));log.record(second,'delete_requested',specification(name))
        log.complete(second,dict(services=list(reversed(SERVICES)),absence_verified=True,client_admission=False))
        value=log.load()
        assert value['attempts'][0]==original and value['attempts'][-1]['state']=='complete'
        with pytest.raises(SafetyError):log.record(second,'delete_intent',specification('SbieDrv'))


@pytest.mark.parametrize('fault',['id','duplicate','prefix','order','boolean-spec','premature-complete','source','basis'])
def test_invalid_attempt_cannot_replace_durable_history(tmp_path,fault):
    with setup(tmp_path) as log:
        identifier=log.begin(['SbieDrv']);log.record(identifier,'delete_intent',specification('SbieSvc'))
        old=log.path.read_bytes();value=log.load();attempt=value['attempts'][-1]
        if fault=='id':attempt['id']='unknown'
        elif fault=='duplicate':value['attempts'].append(attempt.copy())
        elif fault=='prefix':attempt['absent']=['ClaudeResetBackend']
        elif fault=='order':attempt['services'][0]['spec']=specification('ClaudeResetGateway')
        elif fault=='boolean-spec':attempt['services'][0]['spec']['error']=True
        elif fault=='premature-complete':attempt['state']='complete'
        elif fault=='source':value['source_sha256']='0'*64
        else:attempt['state']='assumed_complete'
        with pytest.raises(SafetyError):log.save(value)
        assert log.path.read_bytes()==old


def test_attempt_limit_refuses_new_mutation_before_overwriting_history(tmp_path):
    with setup(tmp_path) as log:
        for _ in range(16):log.begin(list(SERVICES))
        old=log.path.read_bytes()
        with pytest.raises(SafetyError):log.begin(list(SERVICES))
        assert log.path.read_bytes()==old
