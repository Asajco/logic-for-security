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