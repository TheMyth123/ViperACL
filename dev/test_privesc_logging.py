import os
import sys
import unittest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.privesc.modules.shared import (
    format_add_group_member_messages,
    format_force_change_password_messages,
    format_memberof_passive_message,
)


class ForceChangePasswordMessagesTest(unittest.TestCase):
    def test_force_change_password_messages_success(self):
        messages = format_force_change_password_messages(
            "AHMAD_IT@VIPERTECH.LOCAL",
            "ViperStrike2026!",
            success=True,
        )

        self.assertEqual(
            messages["action_message"],
            'Changing the password of user AHMAD_IT@VIPERTECH.LOCAL to "ViperStrike2026!"',
        )
        self.assertEqual(
            messages["result_message"],
            'Password of user AHMAD_IT@VIPERTECH.LOCAL successfully set to "ViperStrike2026!"',
        )
        self.assertEqual(
            messages["context_message"],
            "Context changed to user AHMAD_IT@VIPERTECH.LOCAL successfully.",
        )

    def test_force_change_password_messages_failure(self):
        messages = format_force_change_password_messages(
            "AHMAD_IT@VIPERTECH.LOCAL",
            "ViperStrike2026!",
            success=False,
        )

        self.assertEqual(
            messages["action_message"],
            'Changing the password of user AHMAD_IT@VIPERTECH.LOCAL to "ViperStrike2026!"',
        )
        self.assertEqual(
            messages["result_message"],
            "Password change failed for user AHMAD_IT@VIPERTECH.LOCAL.",
        )
        self.assertIsNone(messages["context_message"])

    def test_add_group_member_messages_success(self):
        messages = format_add_group_member_messages(
            "bob_HR",
            "IT_HELPDESK@VIPERTECH.LOCAL",
            success=True,
        )

        self.assertEqual(
            messages["action_message"],
            "Adding bob_HR into IT_HELPDESK@VIPERTECH.LOCAL group",
        )
        self.assertEqual(
            messages["result_message"],
            "Successfully added bob_HR to IT_HELPDESK@VIPERTECH.LOCAL group.",
        )
        self.assertEqual(
            messages["context_message"],
            "Context changed to user bob_HR successfully.",
        )

    def test_memberof_passive_message(self):
        messages = format_memberof_passive_message()

        self.assertIsNone(messages["action_message"])
        self.assertEqual(messages["result_message"], "Passive module, no actions needed.")
        self.assertIsNone(messages["context_message"])


if __name__ == "__main__":
    unittest.main()
