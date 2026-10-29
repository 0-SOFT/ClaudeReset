"""Read-only, transaction-consistent observation of the initial deny set.

This snapshot never authorizes deletion, installation completion or admission.
The caller supplies rules reconstructed from protected held staging, not keys
from an untrusted receipt. Only exact complete presence or complete absence is
classified; partial, altered and inaccessible state is an error.
"""
from ctypes import wintypes as W
from .strict_wfp import Engine,Rule,BLOCK
from .safeio import SafetyError

READ_ONLY=0x1  # FWPM_TXN_READ_ONLY, pinned Windows SDK fwpmu.h


def observe_initial_denies(engine,rules,verify_closed):
    if (not isinstance(engine,Engine) or engine.dynamic is not False or engine._transaction is not False
            or not engine.handle or not callable(verify_closed)):
        raise SafetyError('Idle persistent engine and closed-boundary verifier required')
    if not isinstance(rules,list) or len(rules)!=16:raise SafetyError('Exact sixteen initial denies required')
    keys=[]
    for rule in rules:
        if type(rule) is not Rule or rule.action!=BLOCK or rule.persistent is not True:
            raise SafetyError('Only initial persistent denies may be observed')
        rule.validate();keys.append(rule.key.value())
    if len(set(keys))!=16:raise SafetyError('Duplicate initial deny identity')
    def closed():
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
    closed()
    engine._call('FwpmTransactionBegin0',[W.HANDLE,W.DWORD],engine.handle,READ_ONLY)
    engine._transaction=True
    try:
        closed();layer=engine.existing_sublayer();actual=engine.own_keys()
        present=[engine.exists_verified(rule) for rule in rules]
        if type(layer) is not bool or type(actual) is not set or any(type(v) is not bool for v in present):
            raise SafetyError('Incomplete initial deny observation')
        if layer and actual==set(keys) and all(present):state='present'
        elif not layer and not actual and not any(present):state='absent'
        else:raise SafetyError('Initial deny set is partial or has additional objects')
        closed()
    finally:
        # No commit and no Add/Delete/Set API is used by this operation.
        # Keep the transaction marked active if termination is uncertain.
        engine._call('FwpmTransactionAbort0',[W.HANDLE],engine.handle)
        engine._transaction=False
    closed()
    return dict(keys=keys,state=state,transaction_consistent=True,settings_changed=False,client_admission=False)
