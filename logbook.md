# Logbook

## Signup protocol

### Version 1:

```
Protocol: Signup

Types:
  Agent U,W,s;
  Number NU1,NU2, NW, NS;
  Function pk,hash, pw

Knowledge:
  U: U,W,s,pk(s),pk(U),inv(pk(U)),pw(U,s),hash;
  W: W,U,s,pk(W),inv(pk(W)),pk(s),pk(U),hash;
  s: s,U,W,pk(s),inv(pk(s)),pk(W),pw(U,s),hash
where U != W

Actions:
  U->s: U,W,{pw(U,s), pk(U), NU1}pk(s)
  s->U: {pk(W),W}inv(pk(s))
  U->W: {NU2, U}pk(W)
  W->s: W,U
  s->W: {pk(U),U}inv(pk(s))
  W->U: {NU2, NW}pk(U)
  U->W: {NW}pk(W)

Goals:
  W authenticates U on NU2
  U authenticates W on NW
  NU2,NW secret between U,W
  pw(U,s) guessable secret between U,s#
```

Gives the OFMC output:

```
Open-Source Fixedpoint Model-Checker version 2024
INPUT:
   logic-for-security/signup/signUp_new2 copy.AnB
SUMMARY:
  ATTACK_FOUND
GOAL:
  weak_auth
BACKEND:
  Open-Source Fixedpoint Model-Checker version 2024
STATISTICS:
  TIME 2212875 ms
  parseTime 0 ms

ATTACK TRACE:
(x1301,1) -> i: x1301,x1302,{pw(x1301,s),pk(x1301),NU1(1)}_(pk(s))
(x1302,2) -> i: x1302,i,{pw(x1302,s),pk(x1302),NU1(2)}_(pk(s))
i -> (s,1): x1302,i,{pw(x1302,s),pk(x1302),NU1(2)}_(pk(s))
(s,1) -> i: {pk(i),i}_inv(pk(s))
i -> (s,2): x1301,x1302,{pw(x1301,s),pk(x1301),NU1(1)}_(pk(s))
(s,2) -> i: {pk(x1302),x1302}_inv(pk(s))
i -> (x1301,1): {pk(x1302),x1302}_inv(pk(s))
(x1301,1) -> i: {NU2(5),x1301}_(pk(x1302))
i -> (x1302,2): {pk(i),i}_inv(pk(s))
(x1302,2) -> i: {NU2(6),x1302}_(pk(i))
i -> (s,2): x1302,x1301
(s,2) -> i: {pk(x1301),x1301}_inv(pk(s))
i -> (x1301,1): {NU2(6),x1302}_(pk(x1301))
(x1301,1) -> i: x1301,x1302
i -> (x1301,1): {pk(x1302),x1302}_inv(pk(s))
(x1301,1) -> i: {NU2(6),NW(9)}_(pk(x1302))
i -> (x1302,2): {NU2(6),NW(9)}_(pk(x1302))
(x1302,2) -> i: {NW(9)}_(pk(i))
i -> (x1301,1): {NW(9)}_(pk(x1301))


% Reached State:
%
% request(x1301,x1302,pWUNU2,NU2(6),1)
% state_rW(x1301,3,hash,pk(x1302),pk(s),inv(pk(x1301)),pk(x1301),s,x1302,inv(pseudonym(x1301)),inv(confChCr(x1301)),inv(authChCr(x1301)),pseudonym(x1301),NU2(6),{NU2(6),x1302}_(pk(x1301)),x1301,x1302,{pk(x1302),x1302}_inv(pk(s)),NW(9),{NU2(6),NW(9)}_(pk(x1302)),{NW(9)}_(pk(x1301)),1)
% state_rW(x38,0,hash,pk(x39),pk(s),inv(pk(x38)),pk(x38),s,x39,inv(pseudonym(x38)),inv(confChCr(x38)),inv(authChCr(x38)),pseudonym(x38),2)
% state_rs(s,2,hash,pw(x1301,s),pk(x1302),inv(pk(s)),pk(s),x1302,x1301,inv(pseudonym(s)),inv(confChCr(s)),inv(authChCr(s)),pseudonym(s),NU1(1),pk(x1301),{pw(x1301,s),pk(x1301),NU1(1)}_(pk(s)),x1301,x1302,{pw(x1301,s),pk(x1301),NU1(1)}_(pk(s)),{pk(x1302),x1302}_inv(pk(s)),x1302,x1301,{pk(x1301),x1301}_inv(pk(s)),2)
% state_rU(x1302,3,hash,pw(x1302,s),inv(pk(x1302)),pk(x1302),pk(s),s,i,inv(pseudonym(x1302)),inv(confChCr(x1302)),inv(authChCr(x1302)),pseudonym(x1302),NU1(2),x1302,i,{pw(x1302,s),pk(x1302),NU1(2)}_(pk(s)),x710,pk(i),{pk(i),i}_inv(pk(s)),NU2(6),{NU2(6),x1302}_(pk(i)),NW(9),{NU2(6),NW(9)}_(pk(x1302)),{NW(9)}_(pk(i)),2)
% state_rs(s,1,hash,pw(x1302,s),pk(i),inv(pk(s)),pk(s),i,x1302,inv(pseudonym(s)),inv(confChCr(s)),inv(authChCr(s)),pseudonym(s),NU1(2),pk(x1302),{pw(x1302,s),pk(x1302),NU1(2)}_(pk(s)),x1302,i,{pw(x1302,s),pk(x1302),NU1(2)}_(pk(s)),{pk(i),i}_inv(pk(s)),1)
% state_rU(x1301,2,hash,pw(x1301,s),inv(pk(x1301)),pk(x1301),pk(s),s,x1302,inv(pseudonym(x1301)),inv(confChCr(x1301)),inv(authChCr(x1301)),pseudonym(x1301),NU1(1),x1301,x1302,{pw(x1301,s),pk(x1301),NU1(1)}_(pk(s)),x610,pk(x1302),{pk(x1302),x1302}_inv(pk(s)),NU2(5),{NU2(5),x1301}_(pk(x1302)),1)
% witness(x1301,x1302,pWUNU2,NU2(5))
% witness(x1302,i,pWUNU2,NU2(6))
% contains(secrecyset(s,2,ppwUs),s)
% contains(secrecyset(s,2,ppwUs),x1301)
% secrets(pw(x1301,s),secrecyset(s,2,ppwUs),i)
% witness(x1301,x1302,pUWNW,NW(9))
% contains(secrecyset(x1302,2,ppwUs),s)
% contains(secrecyset(x1302,2,ppwUs),x1302)
% secrets(pw(x1302,s),secrecyset(x1302,2,ppwUs),i)
% request(x1302,i,pUWNW,NW(9),2)
```

#### What went wrong

In this version a man-in-the-middle attack is performed by the intruder combined with replay and manipulation.

x1301 belives it is registering with website x1302. However, due to the intruder's manipulation, x1301 is actually authenticating with the _intruder_ acting as the website x1302. User x1301 is tricked into believing they are communicating with the legitimate website because the intruder forwards seemingly valid certificates and confirmation messages.

### Version 2

```
Protocol: Signup

Types:
  Agent U,W,s;
  Number NU1,NU2, NW, NS;
  Function pk,hash, pw

Knowledge:
  U: U,W,s,pk(s),pk(U),inv(pk(U)),pw(U,s),hash;
  W: W,U,s,pk(W),inv(pk(W)),pk(s),pk(U),hash;
  s: s,U,W,pk(s),inv(pk(s)),pk(W),pw(U,s),hash
where U != W

Actions:
  U->s: U,W,{pw(U,s), pk(U), NU1}pk(s)
  s->U: {pk(W),W}inv(pk(s))
  U->W: {NU2, U}pk(W)
  W->s: W,U
  s->W: {pk(U),U}inv(pk(s))
  W->U: {NU2, NW, W}pk(U)
  U->W: {NW}pk(W)

Goals:
  W authenticates U on NU2
  U authenticates W on NW
  NU2,NW secret between U,W
  pw(U,s) guessable secret between U,s#
```

Gives the OFMC output:

```
INPUT:
   logic-for-security/signup/signUp_new2 copy.AnB
SUMMARY:
  NO_ATTACK_FOUND
GOAL:
  as specified
DETAILS:
  BOUNDED_NUMBER_OF_SESSIONS
BACKEND:
  Open-Source Fixedpoint Model-Checker version 2024
STATISTICS:
  TIME 2157230 ms
  parseTime 1 ms
```

## Offer upload protocol

```
Types:
   Agent U, W;            # U = User (seller), W = Website
   Number N1, N2;         # Nonces for freshness
   Function pk, sk, hash, offer;
   Constant ACCEPTED;     # Acceptance message


Knowledge:
   U: U, W, pk(W), sk(U), pk(U), hash, offer;
   W: W, U, pk(U), sk(W), pk(W), hash, offer;


Actions:
   # Step 1: User initiates offer upload with signed offer and plaintext nonce
   U -> W: U, N1, {offer(U)}sk(U), {U, offer(U)}pk(W)


   # Step 2: Website sends challenge with signed response
   W -> U: W, N1, N2, {W, U, N1, N2}sk(W)


   # Step 3: User responds to challenge with signed response
   U -> W: U, N1, N2, {U, W, N1, N2}sk(U)


   # Step 4: Website confirms offer upload success
   W -> U: W, N1, N2, {W, U, N1, N2, ACCEPTED}sk(W)


Goals:
   W authenticates U on N2;         # Website verifies the user's response
   W authenticates U on offer(U);   # Website ensures offer authenticity
   U authenticates W on N1;         # User verifies the website's response

```

Ofmc gave us:

````ATTACK TRACE:
i -> (x401,1): x402,x208,x209,x210
(x401,1) -> i: x401,x208,N2(1),{x401,x402,x208,N2(1)}_(sk(x401))
i -> (x401,1): x402,x208,N2(1),x312
(x401,1) -> i: x401,x208,N2(1),{x401,x402,x208,N2(1),t_Constant(ACCEPTED(2))}_(sk(x401))


% Reached State:
%
% request(x401,x402,pWUofferU,offer(x402),1)
% request(x401,x402,pWUN2,N2(1),1)
% state_rW(x401,2,offer,hash,pk(x401),sk(x401),pk(x402),x402,inv(pseudonym(x401)),inv(confChCr(x401)),inv(authChCr(x401)),pseudonym(x401),x210,x209,x208,x402,x208,x209,x210,N2(1),x401,x208,N2(1),{x401,x402,x208,N2(1)}_(sk(x401)),x313,x312,x402,x208,N2(1),x312,t_Constant(ACCEPTED(2)),x401,x208,N2(1),{x401,x402,x208,N2(1),t_Constant(ACCEPTED(2))}_(sk(x401)),1)
% state_rU(x20,0,offer,hash,pk(x20),sk(x20),pk(x27),x27,inv(pseudonym(x20)),inv(confChCr(x20)),inv(authChCr(x20)),pseudonym(x20),1)
% witness(x401,x402,pUWN1,x208)```


````

### What went wrong:

In this version, a man-in-the-middle attack is performed by the intruder, leveraging replay and manipulation of messages.

User x401 believes it is securely uploading an offer to x402 (the website), but the attacker intercepts and manipulates the authentication process. Specifically:

The intruder replays and alters the challenge response containing N2(1).
The attacker forges a confirmation message {x401, x402, x208, N2(1), ACCEPTED(2)}\_(sk(x401)), making x401 believe that the offer upload was successful even though it was manipulated.
The website may incorrectly accept an offer not actually made by x401 or from an unauthorized source, breaking offer authenticity and website authentication goals.
This compromises the protocol, as the website does not properly authenticate the offer's origin, and the attacker can potentially tamper with the uploaded offers.

## Search protocol

```Protocol: BookMarketSearch


Types:
   Agent U, W;            # U = User (searcher), W = Website
   Number N1, N2;         # Nonces for freshness
   Function pk, sk, hash;   # Cryptographic functions
   Constant QUERY, RESULT;  # Constants for query and result




Knowledge:
   U: U, W, pk(W), sk(U), pk(U), hash;   # User knows the website, keys, and hash
   W: W, U, pk(U), sk(W), pk(W), hash;   # Website knows the user, keys, and hash


Actions:
   # Step 1: User sends search query with nonce
   U -> W: U, N1, QUERY


   # Step 2: Website responds with search results and nonce
   W -> U: W, N1, N2, RESULT, {hash(RESULT)}pk(U)


   # Step 3: User acknowledges receipt of results with nonce
   U -> W: U, N2, {hash(RESULT)}pk(W)


Goals:
   U authenticates W on RESULT   # User verifies the website's response
   W authenticates U on QUERY    # Website ensures the search query is authentic
   U authenticates W on N1       # User verifies the website's response
   W authenticates U on N2       # Website verifies the user's response
```

OFMC gave us following:

```ATTACK TRACE:
(x401,1) -> i: x401,N1(1),t_Constant(QUERY(1))
i -> (x401,1): x402,N1(1),x310,t_Constant(QUERY(1)),x312
(x401,1) -> i: x401,x310,{hash(t_Constant(QUERY(1)))}_(pk(x402))


% Reached State:
%
% request(x401,x402,pUWN1,N1(1),1)
% request(x401,x402,pUWRESULT,t_Constant(QUERY(1)),1)
% state_rU(x401,2,hash,pk(x401),sk(x401),pk(x402),x402,inv(pseudonym(x401)),inv(confChCr(x401)),inv(authChCr(x401)),pseudonym(x401),N1(1),t_Constant(QUERY(1)),x401,N1(1),t_Constant(QUERY(1)),x312,t_Constant(QUERY(1)),x310,x402,N1(1),x310,t_Constant(QUERY(1)),x312,x401,x310,{hash(t_Constant(QUERY(1)))}_(pk(x402)),1)
% witness(x401,x402,pWUN2,x310)
% state_rW(x30,0,hash,pk(x30),sk(x30),pk(x31),x31,inv(pseudonym(x30)),inv(confChCr(x30)),inv(authChCr(x30)),pseudonym(x30),1)
% witness(x401,x402,pWUQUERY,t_Constant(QUERY(1)))
```

### What went wrong

In this version, a man-in-the-middle attack is performed by the intruder, exploiting replay and manipulation of messages.

User x401 believes it is communicating with the legitimate website x402, but due to the intruder's interference, parts of the communication are manipulated. Specifically:

The intruder replays and modifies the nonce N1(1) and the QUERY(1) message.
The attack traces show that x401 sends a request using a pseudonym and an encrypted hash, but the intruder intercepts and manipulates these values.
The intruder replays a previously observed message containing the hashed query and attempts to trick x401 into believing it is talking to x402 while actually communicating with the attacker.
This breaks authentication goals, as x401 does not correctly authenticate x402 on the response, and the attacker can potentially alter or replay search queries.
