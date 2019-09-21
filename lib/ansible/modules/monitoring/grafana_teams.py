#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {
    'status': ['preview'],
    'supported_by': 'community',
    'metadata_version': '1.1'
}

DOCUMENTATION = '''
---
module: grafana_teams
author:
  - Rémi REY (@rrey)
version_added: "2.9"
short_description: Manage Grafana Teams
description:
  - Create/update/delete Grafana Teams through API.
options:
  grafana_url:
    description:
      - The Grafana URL.
    required: true
  name:
    description:
      - The name of the Grafana Team.
    required: true
  email:
    description:
      - The mail address associated with the Team.
    required: true
  url_username:
    description:
      - The Grafana user for API authentication.
    default: admin
    aliases: [ grafana_user ]
  url_password:
    description:
      - The Grafana password for API authentication.
    default: admin
    aliases: [ grafana_password ]
  grafana_api_key:
    description:
      - The Grafana API key.
      - If set, C(url_username) and C(url_password) will be ignored.
'''

EXAMPLES = '''
---
- name: Create a team
  grafana_teams:
      grafana_url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      name: "grafana_working_group"
      email: "foo.bar@example.com"
      state: present

- name: Delete a team
  grafana_teams:
      grafana_url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      name: "grafana_working_group"
      email: "foo.bar@example.com"
      state: absent
'''

RETURN = '''
---
team:
    description: Information about the Team
    returned: On success
    type: complex
    contains:
        avatarUrl:
            description: The url of the Team avatar on Grafana server
            returned: always
            type: string
            sample:
                - "/avatar/a7440323a684ea47406313a33156e5e9"
        email:
            description: The Team email address
            returned: always
            type: string
            sample:
                - "foo.bar@example.com"
        id:
            description: The Team email address
            returned: always
            type: integer
            sample:
                - 42
        memberCount:
            description: The number of Team members
            returned: always
            type: integer
            sample:
                - 42
        name:
            description: The name of the team.
            returned: always
            type: string
            sample:
                - "grafana_working_group"
        orgId:
            description: The organization id that the team is part of.
            returned: always
            type: integer
            sample:
                - 1
'''

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, url_argument_spec, basic_auth_header

__metaclass__ = type


class GrafanaTeamInterface(object):

    def __init__(self, module):
        self._module = module
        # {{{ Authentication header
        self.headers = {"Content-Type": "application/json"}
        if module.params.get('grafana_api_key', None):
            self.headers["Authorization"] = "Bearer %s" % module.params['grafana_api_key']
        else:
            self.headers["Authorization"] = basic_auth_header(module.url_username, module.url_password)
        # }}}
        self.grafana_url = module.params.get("grafana_url")

    def _send_request(self, url, data=None, headers=[], method="GET"):
        if data is not None:
            data = json.dumps(data)

        full_url = "{grafana_url}{path}".format(grafana_url=self._module.params["grafana_url"], path=url)
        resp, info = fetch_url(self._module, full_url, data=data, headers=self.headers, method=method)
        status_code = info["status"]
        if status_code == 404:
            return None
        elif status_code == 401:
            self._module.fail_json(failed=True, msg="Unauthorized to perform action '%s' on '%s' header: %s" % (method, full_url, self.headers))
        elif status_code == 403:
            self._module.fail_json(failed=True, msg="Permission Denied")
        elif status_code == 409:
            self._module.fail_json(failed=True, msg="Team name is taken")
        elif status_code == 200:
            return self._module.from_json(resp.read())
        self._module.fail_json(failed=True, msg="Grafana Teams API answered with HTTP %d" % status_code)

    def create_team(self, name, email):
        url = "/api/teams"
        team = dict(name=name, email=email)
        response = self._send_request(url, data=team, headers=self.headers, method="POST")
        return response

    def get_team(self, name):
        url = "/api/teams/search?name={team}".format(team=name)
        response = self._send_request(url, headers=self.headers, method="GET")
        assert response.get("totalCount") <= 1, "Expected 1 teams, got %d" % response["totalCount"]

        if len(response.get("teams")) == 0:
              return None
        return response.get("teams")[0]

    def update_team(self, team_id, name, email):
        url = "/api/teams/{team_id}".format(team_id=team_id)
        team = dict(name=name, email=email)
        response = self._send_request(url, data=team, headers=self.headers, method="POST")
        return response

    def delete_team(self, team_id):
        url = "/api/teams/{team_id}".format(team_id=team_id)
        response = self._send_request(url, headers=self.headers, method="DELETE")
        return response


def main():
    argument_spec = url_argument_spec()
    # remove unnecessary arguments
    del argument_spec['force']
    del argument_spec['force_basic_auth']
    del argument_spec['http_agent']

    argument_spec.update(
        state=dict(choices=['present', 'absent'], default='present'),
        name=dict(type='str', required=True),
        email=dict(type='str', required=True),
        grafana_url=dict(type='str', required=True),
        url_username=dict(aliases=['grafana_user'], default='admin'),
        url_password=dict(aliases=['grafana_password'], default='admin', no_log=True),
        grafana_api_key=dict(type='str', no_log=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[['url_username', 'url_password']],
        mutually_exclusive=[['url_username', 'url_password'], ['grafana_api_key']],
    )

    state = module.params['state']
    name = module.params['name']
    email = module.params['email']

    grafana_iface = GrafanaTeamInterface(module)

    if state == 'present':
        existing_team = grafana_iface.get_team(name)
        if existing_team is None:
            new_team = grafana_iface.create_team(name, email)
            team = grafana_iface.get_team(name)
            module.exit_json(failed=False, team=team)
        else:
            module.exit_json(failed=False, team=existing_team)
    elif state == 'absent':
        existing_team = grafana_iface.get_team(name)
        if existing_team is None:
            module.exit_json(failed=False, message="No team found")
        else:
            result = grafana_iface.delete_team(existing_team.get("id"))
            module.exit_json(failed=False, message=result.get("message"))

if __name__ == '__main__':
    main()
