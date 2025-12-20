This is an **automated** patch to automatically use the new  nginx conf snippets that should be used for apps that use `proxy_pass` and `fastcgi_pass`, shipped in YunoHost >= 12.1.37~38:
- [fastcgi_params_no_auth](https://github.com/YunoHost/yunohost/blob/dev/conf/nginx/fastcgi_params_no_auth)
- [fastcgi_params_with_auth](https://github.com/YunoHost/yunohost/blob/dev/conf/nginx/fastcgi_params_with_auth)
- [proxy_params_no_auth](https://github.com/YunoHost/yunohost/blob/dev/conf/nginx/proxy_params_no_auth)
- [proxy_params_with_auth](https://github.com/YunoHost/yunohost/blob/dev/conf/nginx/proxy_params_with_auth)

In particular they are meant to:
- a) simplify syntax, stuff were clearly always the same accross plenty of apps such as `fastcgi_param SCRIPT_FILENAME [...]` or `proxy_set_header X-Real-IP $remote_addr;` ...
- b) improve/clarify security aspects, by explicitly including either the `_no_auth` params or `_with_auth` params, depending if the app is to support SSO integration or not. In particular, PHP apps should *not* have a `fastcgi_param REMOTE_USER` statement in their nginx conf. `REMOTE_USER` if often the info used by PHP apps to know which user is connected. The [`fastcgi_params_with_auth` snippet](https://github.com/YunoHost/yunohost/blob/dev/conf/nginx/proxy_params_with_auth#L15) properly defines this variable using the info from SSOwat.

This auto-patch should automatically have used the `_no_auth` or `_with_auth` **depending on the value of `sso` from the `manifest.toml`**. ***PLEASE CAREFULLY DOUBLE CHECK*** wether or not this app is supposed to integrate with the SSO or not, and tweak the `include` statements accordingly if necessary.

Moreover, some special cases may not have been handled automagically, such as a) only one `location` block may require the auth information, but not others, or b) the app may include webdav routes or other routes that still requires the classic "Basic Auth" info - currently it is unclear how to handle this case. Please **CAREFULLY DOUBLE CHECK** these.

Finally, please bear in mind that this is just an **automated** patch and it may not work out of the box.
