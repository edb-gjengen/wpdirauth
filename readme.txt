=== wpDirAuth ===
Contributors: gilzow, stephdau, apokalyptik
Tags: login, authentication, directory, ldap, ldaps
Requires at least: 2.2
Tested up to: 3.4.2
Stable tag: 1.7.6

WordPress directory authentication plugin through LDAP and LDAPS (SSL).

== Description ==

See <http://wordpress.org/extend/plugins/wpdirauth/>

PLEASE NOTE
Beta testers of the 1.7.X branch prior to version 1.7.5, you will need to
deactivate wpdirauth before you updgrade to this latest version. Once you
have installed and network activated the plugin, it will copy your options
from their previous location to the sitemeta table.  You will only need to 
do this once.  This will also work for anyone who was using the 1.6.X 
branch or older and plans on using it in MULTISITE mode.

Version 1.7.5 brings full MULTISITE support.

wpDirAuth allows users of central directory (LDAP) servers to login to
authorized WordPress instances without having to register. The plugin creates
a new account for each directory user on first login so that they have full
access to preferences and functions, as any WP user would.

Activating the plugin will not restrict you to using directory authentication
and you will still be able to both create new WP-only users as well as turn on
public registration in WordPress. You can also assign any privilege levels to
your directory users, and the those users will be referred to their
institutional password policy whenever they would normally able to update 
their WP passwords (on the profile screen, in user edit, etc).

= LDAP/LDAPS =

Authentication should work with most LDAP enabled directory services, such as
OpenLDAP, Apache Directory, Microsoft Active Directory, Novell eDirectory,
Sun Java System Directory Server, and more.

wpDirAuth supports LDAP and LDAPS (SSL) connectivity and can force SSL for
WordPress authentication if it is available on the Web server. It also supports
server connection pools, for pseudo load balancing and fault tolerance, or
multiple source directory authentication.

Because the key used to locate a user's profile in the LDAP server is not
always the same, depending on your LDAP server type and institutional choices,
you can define your own through the wpDirAuth administration tool.

When logging in as a directory user, the WP "remember me" feature is downgraded
from 6 months for regular WP users to only 1 hour, so that institutional
passwords are not overly endangered when accessing WP from public terminals.

= Branding & Notifications =

You can define notifications addressed to your directory users in key WordPress
areas, such as the login screen and the profile edit screen.

Since these admin-editable values support HTML (admin, coders, beware of xss!),
you can point your directory users to central support information related to
functions such as changing their institutional password, a WordPress usage
related policy, etc.

There is also a simple and optional terms of services concept, only implemented
for directory users, which will simply record a one-time acceptance date when
agreed upon. Note that agreeing to the TOS has no effect on the user's level of
access in the system, fact which could change in future version if there is a
demand for it, or through direct code contribution to that effect.


== Download ==

You can download the latest stable version of wpDirAuth from the WordPress
Plugin Finder at the following locations:

* Direct download: <http://downloads.wordpress.org/plugin/wpdirauth.zip>
* WPPF home:       <http://wordpress.org/extend/plugins/wpdirauth/>


== Installation ==

Installing should be a piece of cake and take fewer than ten minutes, provided
you know your directory server(s) information, and that your blog is allowed to
connect and bind to it/them.

Please refer to your friendly neighbourhood LDAP sysadmin for more information.

1. Upload the `wpDirAuth` directory to the `/wp-content/plugins/` directory.
1. Login to your WordPress instance as an admin user.
1. Activate the plugin through the 'Plugins' menu in WordPress.
1. Go to the `Directory Auth.` menu found in the WordPress `Options` section.
1. Enter your directory server(s) information and set your preferences.

You should now be able to login as a directory user.


== Using wpDirAuth ==

Once installed and activated, you will be able to administer your directory
settings through the dedicated plugin configuration tool found under the
`Directory Auth.` menu found in the WordPress `Options` admin section.

Directory Authenticated users can now be pre-added to your wordpress system
and granted roles by going to the `Add Dir Auth User` menu found in the 
Wordpress `Users` admin section. Contextual help for this section is 
available for this section within Wordpress' built-in help menu.

See the inline help found in the tool for more information on the settings.

There is a secondary activation toggle, so you can install and activate the
plugin, check out the options panel, but not immediately accept directory
authentication, or even simply turn the feature on or off at any time.


== Help and Support ==

Please post questions, request for help to the Wordpress plugins forum or 
email <wpdirauth@gilzow.com>.  Please be sure to include 'wpdirauth' in the
subject line.

== TO-DO's ==


== Source and Development ==

wpDirAuth welcomes friendly contributors wanting to lend a hand, be it in
the form of code through SVN patches, user support, platform portability
testing, security consulting, localization help, etc.

The [current] goal is to keep the plugin self-contained (ie: no 3rd-party lib)
for easier security maintenance, while keeping the code clean and extensible.

Focus is on security, features, security, and let's not forget, security.
Unit tests will hopefully be developed and constant security audit performed.

Recurring quality patch contributions will lead to commit privileges to the
project source repository.

Please post questions/requests for help to the wordpress forums and/or 
email <wpdirauth@gilzow.com>

The project source code is available on the WordPress Plugin Repository:

* Stable:     <http://svn.wp-plugins.org/wpdirauth/trunk/>
* Unstable:   <http://svn.wp-plugins.org/wpdirauth/branches/dev/>
* Historical: <http://svn.wp-plugins.org/wpdirauth/tags/>

The Sybversion repository can be browsed and tracked (RSS, etc) through the
WP Plugin Repo source browser at:

* <http://dev.wp-plugins.org/browser/wpdirauth/>

The generated code documentation can be found at:

* <http://labs.tekartist.org/wordpress/wpdirauth/phpdocs/>

The WP Plugin Repo also offers a convenient ticketing system for bug and
task tracking.

* Existing tickets:  <http://dev.wp-plugins.org/query?status=new&status=assigned&status=reopened&group=priority&component=wpdirauth&order=priority>
* Open a new ticket: <http://dev.wp-plugins.org/newticket>


== License ==

[General Public License](http://www.gnu.org/licenses/gpl.html)

Copyrights are listed in chronological order, by contributions.

wpDirAuth: WordPress Directory Authentication, original author
Copyright (c) 2007 Stephane Daury - http://stephane.daury.org/

wpDirAuth and wpLDAP Patch Contributions
Copyright (c) 2007 PKR Internet, LLC - http://www.pkrinternet.com/
 
wpDirAuth Patch Contributions
Copyright (c) 2007 Todd Beverly

wpLDAP: WordPress LDAP Authentication
Copyright (c) 2007 Ashay Suresh Manjure - http://ashay.org/

wpDirAuth Patch Contribution and current maintainer
Copyright (c) 2010, 2011, 2012 Paul Gilzow - http://gilzow.com/

wpDirAuth is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published
by the Free Software Foundation.

wpDirAuth is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


== Project History ==

Originally started from a patched version of wpLDAP (1.02+patch), wpDirAuth has
since then been heavily overhauled and features have been modified and added.
In other words, a classic case of `pimp my lib'` (hopefully for the better).

* Current: wpDirAuth: <http://tekartist.org/labs/wordpress/plugins/wpdirauth/>
* Original: wpLDAP:   <http://ashay.org/?page_id=133>
* wpLDAP Patch:       <http://www.pkrinternet.com/~rbulling/private/wpLDAP-1.02-ssl.patch>

== Changelog ==

PLEASE NOTE Beta testers of the 1.7.X branch prior to version 1.7.5, you will need to deactivate wpdirauth before you updgrade to this latest version. Once you have installed and network activated the plugin, it will copy your options from their previous location to the sitemeta table. You will only need to do this once. This will also work for anyone who was using the 1.6.X branch or older and plans on using it in MULTISITE mode.

= 1.7.6 =
Corrected situation where a new authenticated user logging into a child site in a multisite network was added to the parent site, instead of the child site where they initiated the login. Also, somewhere along the way, I reintroduced a bug that when using authentication groups, the plugin would fail to redirect a successfully logged in user.

= 1.7.5 =
* MULTISITE support, bug fixes, security enhancements

= 1.6.1 = 
* Corrected a bug that would prevent user profiles from successfully being found. Thanks go to jgiangrande for identifying the problem area.

= 1.6.0 = 
* Added `Add Dir Auth User` to Admin User menu.  Now able to pre-add Directory Authenticated users and assign roles where previously users would have to log in first, and then have an admin change their role.   

= 1.5.2 = 
* Added ability to limit logins to specific AD groups. Fixed a bug that produced an incorrect filter when using a single Authentication Group 

= 1.5.1 = 
* Remove default password nag for wpdirauth accounts