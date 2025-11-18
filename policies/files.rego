package config.files

import rego.v1

# Return the PAC file as a string
proxy_pac := pac if {
    pac := io.read_file("data/common/proxy.pac")
}

# Return the app.conf as a string
app_conf := conf if {
    conf := io.read_file("data/common/sample.conf")
}

