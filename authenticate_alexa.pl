:-module(authenticate_alexa,[authenticate_alexa/1]).

:- use_module(library(base64)).
:- use_module(library(clpfd)).
:- use_module(library(crypto)).
:- use_module(library(dif)).
:- use_module(library(listing)).
:- use_module(library(ssl)).
:- use_module(library(uri)).


authenticate_alexa(Request):-
	check_sigchainurl(Request,URL),
	portray_clause(myout,URL),
	get_certs(URL,[ACert|CertsRest]),
	checkcertvalid_time(ACert),
	checkchain([ACert|CertsRest]),
	memberchk(key(Key),ACert),
	base64decodesig_encryptedSig(Request,ESig),
%	httpsbody(Request,Body), %how do we read the body of the request?
        httpsbodybytes(Request,Body),
        portray_clause(myout,'Http Body from httpsbody(Request,Body) :'),
        portray_clause(myout,Body),
	crypto_data_hash(Body,Hash,[encoding(octet)]),
	portray_clause(myout,'Serviced signed Hash:'),
	portray_clause(myout,Hash),
        atom_string(Hash,HashString),
	string_concat("0x",HashString,HashString2),
	number_string(HashNumber,HashString2),
	portray_clause(myout,'Hash as Dec'),
	portray_clause(myout,HashNumber),
	
	signature_pow(ESig,0x010001,Key,ClpfdHash),
	portray_clause(myout,'clpfdhash:'),
	portray_clause(myout,'Got here'),
	portray_clause(myout,ClpfdHash),
        %rsa_verify(Key,Hash,ESig,[type(sha1)]),
	portray_clause(myout,done).



get_certs(URL,Certs):-
   setup_call_cleanup(
        http_open(URL,Stream,[]),
        ssl_peer_certificate_chain(Stream,Certs),
        close(Stream)
          ).

signature_pow(Sig, Exp, P, Pow) :-
        portray_clause(myout,'ESig:'),
	portray_clause(myout,Sig),
	(atom(Sig) -> portray_clause(myout,'it is an atom');portray_clause(myout,'it is not an atom')),
	(number(Sig) -> portray_clause(myout,'it is a number');portray_clause(myout,'it is not a number')),
	atom_string(Sig,Sigstring),
	string_concat("0x",Sigstring,SigString2),
	number_string(SigNumber,SigString2),
	portray_clause(myout,'Exp:'),
	portray_clause(myout,Exp),
	%portray_clause(myout,'P:'),
	%portray_clause(myout,P),
	P =public_key(rsa(P2,_EXP2,_,_,_,_,_,_)),
	%portray_clause(myout,'P just number:'),
        %portray_clause(myout,P2),
	(string(P2) -> portray_clause(myout,'String hex P number');portray_clause(myout,notstring)),
	string_concat("0x",P2,NewString),
	%portray_clause(myout,NewString),
	number_string(P3,NewString),
	portray_clause(myout,'P number as dec:'),
	portray_clause(myout,P3),	
        Pow #= SigNumber^Exp mod P3,
	portray_clause(myout,'Pow'),
	portray_clause(myout,Pow),
	portray_clause(myout,verified).

%! check_sigchainurl(+Request:compound, -Url:atom) is semidet.
%
% Verify the Signature Certificate URL.

check_sigchainurl(Request,URL):-
	memberchk(signaturecertchainurl(URL),Request),
  % The protocol is equal to `https` (case insensitive).
	uri_components(URL, uri_components(https,Authority,Path,_,_)),
  % The hostname is equal to `s3.amazonaws.com` (case insensitive).
  uri_authority_components(
    Authority,
    uri_authority(_,_,'s3.amazonaws.com',Port)
  ),
  % The path starts with `/echo.api/` (case sensitive).
  atom_prefix(Path, '/echo.api/'),
  % If a port is defined in the URL, the port is equal to 443.
  (var(Port) -> true ; Port =:= 443).

checkcertvalid_time(Acert):-
	memberchk(notbefore(NotBefore),Acert),
	memberchk(notafter(NotAfter),Acert),
	get_time(NowA),
	Now is round(NowA),
	Now #>NotBefore,
	Now #<NotAfter.

checkchain(Chain):-
        length(Chain,L),
	L#>1.			%Insure chain has more than one cert
	%portray_clause(myout,Chain),
	%checkchain_h(Chain).
	
checkchain_h([_]). %Reached the root.
checkchain_h(Chain):-
       	Chain =[C1,C2|Rest],
       	memberchk(signature(Sig),C1),
	memberchk(to_be_signed(Signed),C1),
	memberchk(key(Key),C2),
	hex_bytes(Signed,Bytes),
	crypto_data_hash(Bytes,Hash,[algorithm(sha256),encoding(octet)]),
	rsa_verify(Key,Hash,Sig,[type(sha256)]),
	checkchain_h([C2|Rest]).
	
base64decodesig_encryptedSig(Request,Hex):-
	memberchk(signature(B64Sig),Request),
	portray_clause(myout,'base64 encoded sig:'),
	portray_clause(myout,B64Sig),
	base64(ESig,B64Sig),
	atom_codes(ESig,Bytes),
	hex_bytes(Hex,Bytes).
	%portray_clause(myout,'Esig is base64 sig decoded using base64//2:'),
	%portray_clause(myout,ESig).
        %portray_clause(myout,'Can not print esig').

httpsbodybytes(Request,BodyBytes2):-
	memberchk(input(In),Request),
	portray_clause(myout,"Bytes:"),
	mygetbody2(In,BodyBytes,0),
	list_butlast(BodyBytes,BodyBytes2).

mygetbody2(_Stream,[],-1).
mygetbody2(Stream,[Byte|Bytes],Check):-
	dif(Check,-1),
	get_byte(Stream,Byte),
	%portray_clause(myout,Byte),
	mygetbody2(Stream,Bytes,Byte).

list_butlast([X|Xs], Ys) :-                 % use auxiliary predicate ...
   list_butlast_prev(Xs, Ys, X).            % ... which lags behind by one item

list_butlast_prev([], [], _).
list_butlast_prev([X1|Xs], [X0|Ys], X0) :-  
   list_butlast_prev(Xs, Ys, X1).



httpsbody(Request,Body):-
	memberchk(input(In),Request),
	portray_clause(myout,In),
	mygetbody(In,Body). 
	%http_read_data(Request,Body,[]). %I think this is for data posted


mygetbody(Stream,String1):-
	read_string(Stream,"\n","",_E,String1),
	portray_clause(myout,'E Value of read string:'),
	portray_clause(myout,'not printable').
	%portray_clause(myout,E).


