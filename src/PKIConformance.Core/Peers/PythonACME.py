# -*- coding: utf-8 -*-
"""The suite's driver of Python's acme - the library certbot is built on, from
certbot's venv at its pin (build/peers/certbot-requirements.txt) - for what no
client of the command line does against an ACME server:

  key-change          an account's key changed (RFC 8555, section 7.3.5)
  deactivate-authz    an authorization given up (section 7.5.2)
  csr-of-other-names  a CSR of other names than its order's (section 7.4)
  revoke-by-proof     a certificate revoked by another account that proved
                      every name of it (section 7.6)
  issue               a certificate by http-01, the way all of them start

    python3 -I PythonACME.py <arguments.json>

The arguments name the scenario, the directory, the names, the port of
http-01, the e-mail address and where the report and the log go. The report
is JSON: every step with what the server answered - "ok", or the type of its
problem document and its detail - and what the test judges besides: URLs,
statuses, thumbprints, certificates. The driver judges nothing; the test
does, against the server's own state.

Everything ACME in here is acme's: its JWS, its JSON, its nonces, its
requests, its web server of http-01. The inner JWS of a key change is acme's
JWS too, signed by josepy - acme has no call for a key change, and certbot
has none either.
"""

import base64
import datetime
import importlib.metadata
import json
import logging
import sys
import traceback

import josepy as jose
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acme import challenges, client, crypto_util, errors, jws, messages, standalone


USER_AGENT = "pkiconformance-python-acme"


class Abort(Exception):
    """A step the rest of the scenario needs did not succeed."""


class Report:
    """What each step got from the server, and the values the test judges."""

    def __init__(self):
        self.steps = []
        self.values = {}

    def step(self, name, call, required=True):
        """Run one step and keep what the server said. A required step that
        fails ends the scenario: what follows it would only fail of it."""
        entry = {"step": name}
        self.steps.append(entry)
        try:
            result = call()
            entry["ok"] = True
            return result
        except messages.Error as error:
            entry["ok"] = False
            entry["problem"] = error.typ
            entry["detail"] = error.detail
        except errors.ConflictError as conflict:
            entry["ok"] = False
            entry["conflict"] = conflict.location
        except Exception as error:  # pylint: disable=broad-except
            entry["ok"] = False
            entry["exception"] = f"{type(error).__name__}: {error}"
        if required:
            raise Abort(name)
        return None


#region Keys, clients, accounts, orders

def deadline(seconds=90):
    return datetime.datetime.now() + datetime.timedelta(seconds=seconds)


def new_key():
    """An account key of P-256: ES256."""
    return jose.JWKEC(key=ec.generate_private_key(ec.SECP256R1()))


def thumbprint(key):
    """RFC 7638's thumbprint of the key, base64url - josepy's computation."""
    return base64.urlsafe_b64encode(key.thumbprint()).rstrip(b"=").decode()


def new_client(args, key):
    net = client.ClientNetwork(key, alg=jose.ES256, user_agent=USER_AGENT)
    return client.ClientV2(client.ClientV2.get_directory(args["directory"], net), net)


def register(acme, email):
    return acme.new_account(messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True))


def csr_for(names):
    """A key of P-256 and acme's CSR of the names."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return crypto_util.make_csr(pem, names)


def prove(acme, orderr, port):
    """Every pending authorization of the order proven by http-01 - acme's
    own web server of it on the port - and the order with its authorizations
    as the server has them then."""
    resources = set()
    answers = []
    for authzr in orderr.authorizations:
        if authzr.body.status == messages.STATUS_VALID:
            continue
        challb = next(challb for challb in authzr.body.challenges if isinstance(challb.chall, challenges.HTTP01))
        response, validation = challb.response_and_validation(acme.net.key)
        resources.add(standalone.HTTP01RequestHandler.HTTP01Resource(chall=challb.chall, response=response, validation=validation))
        answers.append((challb, response))
    servers = standalone.HTTP01DualNetworkedServers(("", port), resources)
    servers.serve_forever()
    try:
        for challb, response in answers:
            acme.answer_challenge(challb, response)
        return acme.poll_authorizations(orderr, deadline())
    finally:
        servers.shutdown_and_server_close()


def ready_order(r, acme, args, names, label=""):
    """A new order of the names, proven: ready to be finalized."""
    csr = csr_for(names)
    orderr = r.step(f"newOrder{label}", lambda: acme.new_order(csr))
    return r.step(f"http-01{label}", lambda: prove(acme, orderr, args["port"]))


def name_of(status):
    """A status as its name: acme keeps an account's as a text, an
    authorization's as a constant of its own."""
    return status if status is None or isinstance(status, str) else status.to_partial_json()


def status_of(acme, url):
    """The status of an object of the server, by POST-as-GET."""
    return acme._post_as_get(url).json().get("status")  # pylint: disable=protected-access

#endregion


#region Scenarios

def issue(args, r):
    """A certificate by http-01 of acme's own web server."""
    acme = new_client(args, new_key())
    regr = r.step("newAccount", lambda: register(acme, args["email"]))
    r.values["account"] = regr.uri
    orderr = ready_order(r, acme, args, args["names"])
    orderr = r.step("finalize", lambda: acme.finalize_order(orderr, deadline()))
    r.values["fullchain"] = orderr.fullchain_pem


def key_change(args, r):
    """Section 7.3.5: the account's key changed - an inner JWS signed by the
    new key, of the account and the old key, inside an outer one of the old -
    then found by the new key, and by the old one no more."""
    old = new_key()
    acme = new_client(args, old)
    regr = r.step("newAccount", lambda: register(acme, args["email"]))
    r.values["account"] = regr.uri
    r.values["old thumbprint"] = thumbprint(old)

    new = new_key()
    r.values["new thumbprint"] = thumbprint(new)
    url = acme.directory["keyChange"]
    payload = json.dumps({"account": regr.uri, "oldKey": old.public_key().to_json()}).encode()
    inner = jws.JWS.sign(payload, key=new, alg=jose.ES256, nonce=None, url=url)
    r.step("keyChange", lambda: acme._post(url, inner))  # pylint: disable=protected-access

    # The new key finds the account (onlyReturnExisting, section 7.3.1) and
    # reads it; the old one finds none.
    by_new = new_client(args, new)
    found = r.step("the account by its new key", lambda: by_new.query_registration(regr), required=False)
    if found is not None:
        r.values["found by the new key"] = found.uri
        r.values["status by the new key"] = name_of(found.body.status)
    r.step("the account by its old key", lambda: new_client(args, old).query_registration(regr), required=False)


def deactivate_authz(args, r):
    """Section 7.5.2: an authorization of a ready order given up - and then
    neither that order nor a new one of the name is issued on it."""
    acme = new_client(args, new_key())
    regr = r.step("newAccount", lambda: register(acme, args["email"]))
    r.values["account"] = regr.uri
    orderr = ready_order(r, acme, args, args["names"])
    authzr = orderr.authorizations[0]
    r.values["authorization"] = authzr.uri

    deactivated = r.step("deactivate the authorization", lambda: acme.deactivate_authorization(authzr))
    r.values["status it answered"] = name_of(deactivated.body.status)
    r.values["status of the authorization after"] = r.step("the authorization after", lambda: status_of(acme, authzr.uri), required=False)
    r.values["status of the order after"] = r.step("the order after", lambda: status_of(acme, orderr.uri), required=False)

    finalized = r.step("finalize the order", lambda: acme.finalize_order(orderr, deadline(30)), required=False)
    if finalized is not None:
        r.values["fullchain"] = finalized.fullchain_pem

    csr = csr_for(args["names"])
    nextr = r.step("newOrder of the name again", lambda: acme.new_order(csr), required=False)
    if nextr is not None:
        r.values["next authorizations"] = [authz.uri for authz in nextr.authorizations]
        r.values["next authorization statuses"] = [name_of(authz.body.status) for authz in nextr.authorizations]


def csr_of_other_names(args, r):
    """Section 7.4: a ready order finalized with a CSR of other names than
    its own - refused - and then with its own: issued."""
    acme = new_client(args, new_key())
    regr = r.step("newAccount", lambda: register(acme, args["email"]))
    r.values["account"] = regr.uri
    orderr = ready_order(r, acme, args, args["names"])

    other = csr_for(args["other names"])
    refused = r.step("finalize with a CSR of other names", lambda: acme.finalize_order(orderr.update(csr_pem=other), deadline(30)), required=False)
    if refused is not None:
        r.values["fullchain of other names"] = refused.fullchain_pem
    r.values["status of the order after"] = r.step("the order after", lambda: status_of(acme, orderr.uri), required=False)

    finalized = r.step("finalize with its own CSR", lambda: acme.finalize_order(orderr, deadline()), required=False)
    if finalized is not None:
        r.values["fullchain"] = finalized.fullchain_pem


def revoke_by_proof(args, r):
    """Section 7.6: alice's certificate - revoked not by mallory, who proved
    none of its names, but by bob, who proved every one of them."""
    alice = new_client(args, new_key())
    r.step("newAccount of alice", lambda: register(alice, "alice-" + args["email"]))
    orderr = ready_order(r, alice, args, args["names"], " of alice")
    orderr = r.step("finalize of alice", lambda: alice.finalize_order(orderr, deadline()))
    r.values["fullchain"] = orderr.fullchain_pem
    certificate = x509.load_pem_x509_certificate(orderr.fullchain_pem.encode())

    mallory = new_client(args, new_key())
    r.step("newAccount of mallory", lambda: register(mallory, "mallory-" + args["email"]))
    r.step("revoked by mallory, who proved nothing", lambda: mallory.revoke(certificate, 1), required=False)

    bob = new_client(args, new_key())
    r.step("newAccount of bob", lambda: register(bob, "bob-" + args["email"]))
    ready_order(r, bob, args, args["names"], " of bob")
    r.step("revoked by bob, who proved every name", lambda: bob.revoke(certificate, 4), required=False)


def version(args, r):
    r.values["version"] = importlib.metadata.version("acme")


SCENARIOS = {
    "issue":              issue,
    "key-change":         key_change,
    "deactivate-authz":   deactivate_authz,
    "csr-of-other-names": csr_of_other_names,
    "revoke-by-proof":    revoke_by_proof,
    "version":            version,
}

#endregion


def main():

    with open(sys.argv[1], encoding="utf-8") as file:
        args = json.load(file)

    if args.get("log"):
        logging.basicConfig(filename=args["log"], level=logging.DEBUG,
                            format="%(asctime)s %(name)s %(levelname)s %(message)s")

    report = Report()

    try:
        SCENARIOS[args["scenario"]](args, report)
    except Abort as abort:
        report.values["aborted at"] = str(abort)
    except Exception:  # pylint: disable=broad-except
        report.values["exception"] = traceback.format_exc()

    with open(args["report"], "w", encoding="utf-8") as file:
        json.dump({"steps": report.steps, "values": report.values}, file, indent=2)


if __name__ == "__main__":
    main()
