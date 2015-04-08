# php-pingfed-metadata

PHP scripts for managing SAML connections in PingFederate from SAML 2.0 metadata.

Details on the working and configuration of the scripts can be found at the top
of the files themselves.

## Tips & Tricks

- you need to enable the Connection Management SOAP API in the section `Server Configuration -> Application Authentication -> Connection Management`
  and make sure that you put in a username/password that matches the one configured at the top of the script

- make sure you've enabled the required protocol support in the Server Settings, e.g. if you want to create/manage SAML 1.1 connections,
  be sure to enable that role under `Server Configuration -> Server Settings -> Roles & Protocols`.
  
- for a large number of connections you'd want to disable "automatic connection validation" in the section `Server Configuration -> Server Settings -> System Options`

- for a large number of connections you need to patch the Jetty configuration to avoid the error `Form too many keys` by adding the
  following two entries to `pingfederate/etc/jetty-admin.xml`
  
      <Call name="setAttribute">
        <Arg>org.eclipse.jetty.server.Request.maxFormKeys</Arg>
        <Arg>10000</Arg>
      </Call>

      <Call name="setAttribute">
        <Arg>org.eclipse.jetty.server.Request.maxFormContentSize</Arg>
        <Arg>300000</Arg>
      </Call>
  