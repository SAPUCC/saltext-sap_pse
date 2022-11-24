# SaltStack SAP PSE extension
This SaltStack extensions allows managing SAP Personal Security Environment (PSE) files.

**THIS PROJECT IS NOT ASSOCIATED WITH SAP IN ANY WAY**

## Installation
Run the following to install the SaltStack SAP PSE extension:
```bash
salt-call pip.install saltext.sap-pse
```
Keep in mind that this package must be installed on every minion that should utilize the states and execution modules.

Alternatively, you can add this repository directly over gitfs
```yaml
gitfs_remotes:
  - https://github.com/SAPUCC/saltext-sap_pse.git:
    - root: src/saltext/sap_pse
```
In order to enable this, logical links under `src/saltext/sap_pse/` from `_<dir_type>` (where the code lives) to `<dir_type>` have been placed, e.g. `_modules` -> `modules`. This will double the source data during build, but:
 * `_modules` is required for integrating the repo over gitfs
 * `modules` is required for the salt loader to find the modules / states

## Usage
A state using the SAP PSE extension looks like this:
```jinja
SAP Host Agent SAPSSLS PSE file is managed:
  sap_pse.managed:
    - name: /usr/sap/hostctrl/exe/sec/SAPSSLS.pse
    - user: sapadm
    - group: sapsys
    - seclogons:
      - sapadm
    - priv_key: /etc/pki/{{ grains["id"] }}.key
    - pub_key: /etc/pki/{{ grains["id"] }}.crt
```

## Docs
See https://saltext-sap-pse.readthedocs.io/ for the documentation.

## Contributing
We would love to see your contribution to this project. Please refer to `CONTRIBUTING.md` for further details.

## License
This project is licensed under GPLv3. See `LICENSE.md` for the license text and `COPYRIGHT.md` for the general copyright notice.
