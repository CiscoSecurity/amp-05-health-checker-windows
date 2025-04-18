'''
Main Page of Secure Endpoint Health Checker.  This is to help customer's identify their own issues without \
    having to open a TAC case.
'''
import logging
import popups
import PySimpleGUI as sg
import time
import webbrowser
from data import Data


def main():
    """
    This is the main function that ties all other components together:
    """

    logging.basicConfig(
        format='%(asctime)s %(name)-12s %(levelname)-8s %(filename)s %(funcName)s %(message)s',
        datefmt='%m-%d %H:%M:%S',
        level=logging.INFO,
        filename="amp_health_checker_log.log"
        )
    logging.warning(f"Secure Endpoint Health Checker logging level is {logging.getLevelName(logging.getLogger().level)}")
    logging.debug(f"{time.ctime()}: Starting Health Checker")

    x_count = 0

    button_size = (20, 1)
    layout = [
        [sg.Text("SE Version: ", tooltip="The current Secure Endpoint version running on the system."), \
            sg.Text("Loading...", key='_version')],
        [sg.Text("CPU Usage: ", tooltip="The current amount of CPU utilized by Secure Endpoint executables."), \
            sg.Text("0", key='_cpu', size=(8, 1))],
        [sg.Text("SE Uptime: ", size=(10, 1)), sg.Text("", size=(27, 1), key="_uptime", \
            tooltip="Time since Secure Endpoint was last stopped")],
        [sg.Text("Isolation: ", tooltip="Shows if the connector is Isolated or Not Isolated. \
            Refresh with Refresh button."), sg.Text("", size=(12, 1), key="_isolated"),
         sg.Text("", tooltip="If Isolated, shows the unlock code. Requires valid API Credentials \
             .", size=(17, 1), key="_unlock_code")],
        [sg.Text("Connector UUID: ", size=(12, 1)), sg.Text("", size=(30, 1), key="_connector_uuid", \
            tooltip="UUID of the local connector")],
        [sg.Text('_'*50)],
        [sg.Text("TETRA Version: ", size=(12, 1)), sg.Text("", size=(7, 1), key="_tetra_version", \
            tooltip="Shows the local TETRA version.\nGreen if up to date.\nYellow if not within \
                last 5 or connectivity error to API.\nRed if TETRA is not enabled."),
         sg.Button('Check TETRA Version', size=button_size, button_color=('black', '#F0F0F0'), \
            key='_tetra_version_button', tooltip="Checks the API to see if TETRA is up to date. \
                Requires Valid API Credentials.")],
        [sg.Text("", key="_latest_tetra_version", size=(8, 1))],
        [sg.Text("Policy Serial: ", size=(12, 1)), sg.Text("", size=(7, 1), \
            key="_policy_version", tooltip="Shows the current policy serial number.\nGreen \
                if this matches the cloud version.\nYellow if there is a connectivity issue or \
                    invalid API Credentials.\nRed if the local policy doesn't match the cloud \
                        version.  Try syncing policy."),
         sg.Button("Check Policy Version", size=button_size, button_color=('black', '#F0F0F0'), \
            key='_policy_version_button', tooltip="Checks the API to see if the policy is up \
                to date.")],
        [sg.Text("", key="_latest_policy_version", size=(20, 1))],
        [sg.Text("API Credentials: ", size=(13, 1), tooltip='Shows if the currently stored API \
            Credentials are valid. Can read from text file named "apiCreds.txt" in the local \
                directory.\nMust be in this format:\nclient_id="abcdabcdabcdabcdabcd"\napi_key= \
                    "abcd1234-abcd-1234-abcd-abcd1234abcd"'), sg.Text("", size=(6, 1), \
                        key="_api_cred_valid")],
        [sg.Text('_'*50)],
        [sg.Button("Live Debugging", button_color=('black', '#F0F0F0'), size=button_size, \
            tooltip="Live analysis used for determining potential exclusions."), \
                sg.Button("Run Analysis", button_color=('black', '#F0F0F0'), size=button_size, \
                tooltip="Runs analysis on the sfc.exe.log file to provide information on potential \
                        exclusions.")],
        [sg.Button("Live Top Processes", button_color=('black', '#F0F0F0'), size=button_size, \
            tooltip="Shows the top processes seen on the system in a live view."), \
                sg.Button("Check Certs", button_color=('black', '#F0F0F0'), size=button_size, \
                    tooltip="Check system for installation of required certificates.")],
        [sg.Button("Connectivity Test", button_color=('black', '#F0F0F0'), size=button_size, \
            key="_connectivity_test", tooltip="Test connection to the required servers for \
                SE operations."), sg.Button("Check Engines", button_color=('black', '#F0F0F0'), \
                    size=button_size, tooltip="Provides a quick view of which SE engines \
                        are enabled on the system.")],
        [sg.Button("Generate Diagnostic", button_color=('black', '#F0F0F0'), size=button_size, \
            tooltip="Generate SE diagnostic bundle with SE Health Checker log. Both files \
                will be on the desktop."), \
                sg.Button("Manual SFC Analysis", button_color=('black', '#F0F0F0'), \
                    size=button_size, tooltip="Allows importing external sfc.exe.log \
                        files for analysis.")],
        [sg.Button("View Exclusions", button_color=('black', '#F0F0F0'), size=button_size, \
            tooltip="Shows the file and process exclusions from the local policy."),
                sg.Button("Recommend Exclusions", button_color=('black', '#F0F0F0'), size=button_size, \
                tooltip="Check processes seen versus Cisco Maintained Exclusions lists and make recommendations.")],
        [sg.Text('Log Level:', tooltip="Select higher log level if requested by the \
            tool developers.", size=(9, 1)), sg.Button('INFO', button_color=('white', 'green'), \
                key='_INFO', size=(9, 1)), sg.Button('WARNING', button_color=('black', '#F0F0F0'), \
                    key="_WARNING", size=(9, 1)), sg.Button('DEBUG', button_color=('black', '#F0F0F0'), \
                        key="_DEBUG", size=(9, 1))],
        [sg.Text("", size=(9, 1)),
            sg.Button("Links", size=(9, 1), button_color=('black', '#F0F0F0')),
            sg.Button("Refresh", size=(9, 1), button_color=('black', '#F0F0F0'),
                tooltip="Refreshes calculated data, including Isolation Status."),
            sg.Button("Cancel", button_color=('black', '#F0F0F0'), \
                tooltip="Exits the program.", size=(9, 1))],
        [sg.Push(), sg.Text("Leave Feedback", enable_events=True, text_color='blue', key='Feedback'), sg.Push()]
    ]
    logging.debug('test')
    window = sg.Window("SE Health Check", layout)

    is_first = True

    while True:
        if is_first:
            event, values = window.Read(timeout=0)
            logging.debug(f"Event - {event} : Values - {values}")
            d_instance = Data()
            is_first = False
        else:
            event, values = window.Read(timeout=5000)

        if x_count < 10:
            x_count += 1
        else:
            if d_instance.api_cred_valid:
                d_instance.update_api_calls()
            x_count = 0
        d_instance.update()
        logging.debug(f'Self Scan Count = {d_instance.internal_health_check}')
        window.find_element('_version').Update(d_instance.version)
        window.find_element('_cpu').Update(d_instance.current_cpu)
        window.find_element('_uptime').Update(d_instance.converted_uptime)
        window.find_element('_tetra_version').Update(d_instance.tetra_version_display)
        window.find_element('_policy_version').Update(d_instance.policy_dict['policy_sn'])
        window.find_element('_api_cred_valid').Update('Valid' if d_instance.api_cred_valid \
             else 'Invalid')
        window.find_element('_isolated').Update(d_instance.isolated)
        window.find_element('_unlock_code').Update(d_instance.unlock_code)
        window.find_element('_connector_uuid').Update(d_instance.local_uuid)
        if event in (None, "Cancel"):
            break
        elif event == "_INFO":
            logging.getLogger().setLevel(logging.INFO)
            logging.info(f'Log level changed to {logging.getLevelName(logging.getLogger().level)}')
            window.find_element('_INFO').Update(button_color=('white', 'green'))
            window.find_element('_WARNING').Update(button_color=('black', '#F0F0F0'))
            window.find_element('_DEBUG').Update(button_color=('black', '#F0F0F0'))
            window.Refresh()
        elif event == '_WARNING':
            logging.getLogger().setLevel(logging.WARNING)
            logging.warning(f'Log level changed to {logging.getLevelName(logging.getLogger().level)}')
            window.find_element('_INFO').Update(button_color=('black', '#F0F0F0'))
            window.find_element('_WARNING').Update(button_color=('white', 'green'))
            window.find_element('_DEBUG').Update(button_color=('black', '#F0F0F0'))
            d_instance.verify_api_creds()
            window.Refresh()
        elif event == '_DEBUG':
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug(f'Log level changed to {logging.getLevelName(logging.getLogger().level)}')
            window.find_element('_INFO').Update(button_color=('black', '#F0F0F0'))
            window.find_element('_WARNING').Update(button_color=('black', '#F0F0F0'))
            window.find_element('_DEBUG').Update(button_color=('white', 'green'))
            d_instance.verify_api_creds()
            window.Refresh()
        elif event == "Live Debugging":
            popups.lpap(d_instance)
        elif event == "Live Top Processes":
            popups.just_process(d_instance)
        elif event == "_tetra_version_button":
            popups.check_latest_tetra(d_instance, window)
        elif event == "_policy_version_button":
            popups.check_latest_policy(d_instance, window)
        elif event == "_connectivity_test":
            popups.connectivity(d_instance)
        elif event == "Check Engines":
            popups.engines_enabled(d_instance)
        elif event == "View Exclusions":
            popups.view_exclusions(d_instance)
        elif event == "Run Analysis":
            popups.analysis(d_instance)
        elif event == "Check Certs":
            popups.check_certs()
        elif event == "Refresh":
            d_instance.reset_data()
            window.Refresh()
        elif event == "Manual SFC Analysis":
            popups.manual_sfc(d_instance)
        elif event == "Generate Diagnostic":
            d_instance.generate_diagnostic()
            if d_instance.diag_failed:
                popups.diag_failed_popup()
        elif event == "Recommend Exclusions":
            popups.recommend_exclusions(d_instance)
        elif event == "Links":
            popups.links_popup()
        elif event == "Feedback":
            webbrowser.open('https://github.com/CiscoSecurity/amp-05-health-checker-windows/issues/new')
            window.find_element('Feedback').Update(text_color='purple')
    if d_instance.enabled_debug:
        d_instance.disable_debug()
    window.close()

if __name__ == "__main__":
    main()
