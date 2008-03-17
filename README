=Introduction
TacacsPlus was created in order to facilitate the easy creation of
clients and servers, and thus, the most useful classes are TacacsPlus::Client
and TacacsPlus::Server. Please see the rdoc files for more information on these classes.

I have included a sample Tacacs+ server application which highlights the features
of the TacacsPlus::Server class. This application is located in scripts/tacacs_plus_server.

In order to reduce confusion with the use of this module I have hidden most of the
rdoc documentation relating to the inner workings of this module. If you wish to work
with the raw TACACS+ packets, then please see the documentation within the source itself.

Dustin Spinhirne

=General Description
AAA consists of 3 parts; authentication, authorization, and accounting.
Within each of these functions there are various packet types which
facilitate communication between a client and server. Classes
have been defined to allow the creation of complete TACACS+ packets. Every
packet will contain a header, which is represented by the class TacacsPlus::TacacsHeader.
The body of each packet will be defined by one of the following classes:
 * TacacsPlus::AuthenticationStart
 * TacacsPlus::AuthenticationReply
 * TacacsPlus::AuthenticationContinue
 * TacacsPlus::AuthorizationRequest
 * TacacsPlus::AuthorizationResponse
 * TacacsPlus::AccountingRequest
 * TacacsPlus::AccountingReply

Since many of the fields within the various packet types are interchangable
with each other, I created a module for each packet field which is then mixed into
the appropriate packets. Pay attention to the included modules for
each packet class if you want to know which methods are available for use.

