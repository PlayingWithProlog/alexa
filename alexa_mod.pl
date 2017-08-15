:-module(alexa_mod,[alexa/1]).

:- use_module(library(base64)).
:- use_module(library(clpfd)).
:- use_module(library(crypto)).
:- use_module(library(dif)).
:- use_module(library(http/http_json)).
:- use_module(library(http/http_open)).
:- use_module(library(listing)).
:- use_module(library(ssl)).
:- use_module(library(url)).

:- dynamic sessionid_fact/2.
:-dynamic '$copy'/1.
:-op(600, xfy, '=>').



alexa(Request):-
	/*
	setup_call_cleanup(open('output.txt',append,Stream,[alias(myout)]),
			   authenticate_alexa(Request),
			   close(Stream)),
	*/
	http_read_json_dict(Request,DictIn),
	handle_dict(DictIn,DictOut),
	%my_json_answer(hello,DictOut),
	reply_json(DictOut).

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

check_sigchainurl(Request,URL):-
	memberchk(signaturecertchainurl(URL),Request),
	parse_url(URL,P), %what about normalise url? I dont think it is needed
	memberchk(protocol(https),P),%should make case insenstive
	memberchk(host('s3.amazonaws.com'),P), %should make case insenstive
	memberchk(path(Path),P),
	string_concat('/echo.api/',_,Path),
	(memberchk(port(Port),P) -> Port =443 ; true).
			  
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



handle_dict(DictIn,DictOut) :-
	setup_call_cleanup(
			   open('recieved.txt',append,Stream,[]),
			   (get_id(DictIn,Id),
			    format(Stream,"Id: ~w\n",[Id])),
			   close(Stream)
			  ),
	application_id(Id),
	get_intent(DictIn,IntentName),
	intent_dictOut(IntentName,DictIn,DictOut).

handle_dict(_DictIn,DictOut):-
	DictOut = _{
	      shouldEndSession: false,
	      response: _{outputSpeech:_{type: "PlainText", text: "Error Id did not match"}},
              version:"1.0"
	     }.



get_intent(DictIn,IntentName):-
	get_dict(request,DictIn,RequestObject),
	get_dict(intent,RequestObject,IntentObject),
	get_dict(name,IntentObject,IntentName).

/*
 *  Steps needed
* 1. check the app id
  2. Check the time stamp
* 3. Make the json responce
*/


intent_dictOut("getANewFact",_,DictOut):-
	answers(RandomMessage),
	my_json_answer(RandomMessage,DictOut).

intent_dictOut("remember",DictIn,DictOut):-
	get_dict(session,DictIn,SessionObject),
	get_dict(sessionId,SessionObject,SessionId),
	get_dict(request,DictIn,RequestObject),
	get_dict(intent,RequestObject,IntentObject),
	get_dict(slots,IntentObject,SlotsObject),
	get_dict(mySlot,SlotsObject,MySlotObject),
	get_dict(value,MySlotObject,Value),
	split_string(Value," ","",StringList),
	maplist(string_lower,StringList,StringListLow),
	maplist(atom_string,AtomList,StringListLow),
	(phrase(sentence(Rule),AtomList) ->
	 (assertz(sessionid_fact(SessionId,Rule)),
	  my_json_answer(Value,DictOut));
	  my_json_answer(Value,DictOut)).

intent_dictOut("question",DictIn,DictOut):-
	writeln(user_error,walrus),
	get_dict(session,DictIn,SessionObject),
	get_dict(sessionId,SessionObject,SessionId),
	get_dict(request,DictIn,RequestObject),
	get_dict(intent,RequestObject,IntentObject),
	get_dict(slots,IntentObject,SlotsObject),
	get_dict(questionSlot,SlotsObject,MySlotObject),
	get_dict(value,MySlotObject,Value),
	portray_clause(user_error,Value),
	((
	  split_string(Value," ","",StringList),
	  maplist(string_lower,StringList,StringListLow),
	  maplist(atom_string,AtomList,StringListLow),
	
	  phrase(question(Query),AtomList),prove_question(Query,SessionId,Answer)) ->
	 my_json_answer(Answer,DictOut);
	 my_json_answer(Value,DictOut)
	).
	

intent_dictOut(_,_,DictOut):-
	my_json_answer('Error parsing',DictOut).

prove_question(Query,SessionId,Answer):-
	findall(Rule,sessionid_fact(SessionId,Rule),Rulebase),
	prove_rb(Query,Rulebase),
	transform(Query,Clauses),
	phrase(sentence(Clauses),AnswerAtomList),
	atomics_to_string(AnswerAtomList," ",Answer).
	


get_id(Dict,Id):-
	get_dict(session,Dict,SessionObject),
	get_dict(application,SessionObject,ApplicationObject),
	get_dict(applicationId,ApplicationObject,Id).

application_id(X):-
	X= "amzn1.ask.skill.a27eb505-fcef-49bf-8975-3e1a6d7b7c74".

my_json_answer(Message,X):-
	X = _{
	      response: _{
			  shouldEndSession: false,
			  outputSpeech:_{type: "PlainText", text: Message}
			 },
              version:"1.0"
	      
	     }.
	
go:-
	json_write_dict(current_output,_{version:"1.0", shouldEndSession: false, response: _{outputSpeech:_{type: "PlainText", text: "Wally is a walrus"}}}).


answers(X):-
	random_member(X,["walruses can weigh up to 1900 kilograms", "There are two species of walrus - Pacific and Atlantic", "Walruses eat molluscs", "Walruses live in herds","Walruses have two large tusks"]).


string_rule(String,Rule):-
	string_lower(String,StringL),
	split_string(StringL," ","",Split),
	maplist(atom_string,AtomList,Split),
	phrase(sentence(Rule),AtomList).



sentence(C) --> determiner(N,M1,M2,C),
                noun(N,M1),
                verb_phrase(N,M2).

sentence([(L:-true)]) --> proper_noun(N,X),
                          verb_phrase(N,X=>L).

verb_phrase(s,M) --> [is],property(s,M).
verb_phrase(p,M) --> [are], property(p,M).

property(s,M) --> [a], noun(s,M).
property(p,M) --> noun(p,M).

property(_N,X=>mortal(X)) --> [mortal].

determiner(s,X=>B,X=>H,[(H:-B)]) --> [every].
determiner(p, sk=>H1, sk=>H2, [(H1:-true),(H2 :- true)]) -->[some].

proper_noun(s,sam) --> [sam].
noun(s,X=>human(X)) --> [human].
noun(p,X=>human(X)) --> [humans].
noun(s,X=>living_being(X)) --> [living],[being].
noun(p,X=>living_being(X)) --> [living],[beings].


question(Q) --> [who],[is], property(s,_X=>Q).
question(Q) --> [is], proper_noun(N,X),
                property(N,X=>Q).
question((Q1,Q2)) --> [are],[some],noun(p,sk=>Q1),
	property(p,sk=>Q2).





prove_rb(true,_Rulebase):-!.
prove_rb((A,B),Rulebase):-!,
    prove_rb(A,Rulebase),
    prove_rb(B,Rulebase).

prove_rb(A,Rulebase):-
    find_clause((A:-B),Rulebase),
    prove_rb(B,Rulebase).

find_clause(Clause,[Rule|_Rules]):-
    my_copy_element(Clause,Rule).

find_clause(Clause,[_Rule|Rules]):-
    find_clause(Clause,Rules).

transform((A,B),[(A:-true)|Rest]):-!,
    transform(B,Rest).

transform(A,[(A:-true)]).

get_input(Input):-
    write('? '), flush, read(Input).

show_answer(Answer):-
    write('! '), flush, write(Answer),nl.

my_copy_term(Old,New):-
    asserta('$copy'(Old)),
    retract('$copy'(New)),!.
my_copy_term(Old,_New):-
    retract('$copy'(Old)),
    !,fail.

my_copy_element(X,Ys):-
    member(X1,Ys),
    copy_term(X1,X).
