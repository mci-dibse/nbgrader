import os
import shutil
import logging
from zeep import Client
import time
import base64
import xml.etree.ElementTree as ET

from stat import (
    S_IRUSR, S_IWUSR, S_IXUSR,
    S_IRGRP, S_IWGRP, S_IXGRP,
    S_IROTH, S_IWOTH, S_IXOTH
)

from textwrap import dedent
from traitlets import Bool

from .exchange import Exchange
from ..utils import get_username, check_mode, find_all_notebooks


class ExchangeSubmit(Exchange):

    strict = Bool(
        False,
        help=dedent(
            "Whether or not to submit the assignment if there are missing "
            "notebooks from the released assignment notebooks."
        )
    ).tag(config=True)

    add_random_string = Bool(
        True,
        help=dedent(
            "Whether to add a random string on the end of the submission."
        )
    ).tag(config=True)

    def getLogger(self):
        # logger.getLogger returns the cached logger when called multiple times
        # logger.Logger created a new one every time and that avoids adding
        # duplicate handlers
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            logger.setLevel(logging.DEBUG)
            f_handler = logging.FileHandler(os.path.join('/srv/nbgrader/exchange/', self.coursedir.course_id  + '/inbound/nbgrader_submit.log'), 'a')
            f_handler.setLevel(logging.DEBUG)
            f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            f_handler.setFormatter(f_format)
            logger.addHandler(f_handler)
        return logger
        
    def init_src(self):
        if self.path_includes_course:
            root = os.path.join(self.coursedir.course_id, self.coursedir.assignment_id)
            other_path = os.path.join(self.coursedir.course_id, "*")
        else:
            root = self.coursedir.assignment_id
            other_path = "*"
        self.src_path = os.path.abspath(os.path.join(self.assignment_dir, root))
        self.coursedir.assignment_id = os.path.split(self.src_path)[-1]
        if not os.path.isdir(self.src_path):
            self._assignment_not_found(self.src_path, os.path.abspath(other_path))

    def init_dest(self):
        if self.coursedir.course_id == '':
            self.fail("No course id specified. Re-run with --course flag.")
        if not self.authenticator.has_access(self.coursedir.student_id, self.coursedir.course_id):
            self.fail("You do not have access to this course.")

        self.inbound_path = os.path.join(self.root, self.coursedir.course_id, 'inbound')
        if not os.path.isdir(self.inbound_path):
            self.fail("Inbound directory doesn't exist: {}".format(self.inbound_path))
        if not check_mode(self.inbound_path, write=True, execute=True):
            self.fail("You don't have write permissions to the directory: {}".format(self.inbound_path))

        self.cache_path = os.path.join(self.cache, self.coursedir.course_id)
        if self.coursedir.student_id != '*':
            # An explicit student id has been specified on the command line; we use it as student_id
            if '*' in self.coursedir.student_id or '+' in self.coursedir.student_id:
                self.fail("The student ID should contain no '*' nor '+'; got {}".format(self.coursedir.student_id))
            student_id = self.coursedir.student_id
        else:
            student_id = get_username()
        if self.add_random_string:
            random_str = base64.urlsafe_b64encode(os.urandom(9)).decode('ascii')
            self.assignment_filename = '{}+{}+{}+{}'.format(
                student_id, self.coursedir.assignment_id, self.timestamp, random_str)
        else:
            self.assignment_filename = '{}+{}+{}'.format(
                student_id, self.coursedir.assignment_id, self.timestamp)

    def init_release(self):
        if self.coursedir.course_id == '':
            self.fail("No course id specified. Re-run with --course flag.")

        course_path = os.path.join(self.root, self.coursedir.course_id)
        outbound_path = os.path.join(course_path, 'outbound')
        self.release_path = os.path.join(outbound_path, self.coursedir.assignment_id)
        if not os.path.isdir(self.release_path):
            self.fail("Assignment not found: {}".format(self.release_path))
        if not check_mode(self.release_path, read=True, execute=True):
            self.fail("You don't have read permissions for the directory: {}".format(self.release_path))

    def check_filename_diff(self):
        released_notebooks = find_all_notebooks(self.release_path)
        submitted_notebooks = find_all_notebooks(self.src_path)

        # Look for missing notebooks in submitted notebooks
        missing = False
        release_diff = list()
        for filename in released_notebooks:
            if filename in submitted_notebooks:
                release_diff.append("{}: {}".format(filename, 'FOUND'))
            else:
                missing = True
                release_diff.append("{}: {}".format(filename, 'MISSING'))

        # Look for extra notebooks in submitted notebooks
        extra = False
        submitted_diff = list()
        for filename in submitted_notebooks:
            if filename in released_notebooks:
                submitted_diff.append("{}: {}".format(filename, 'OK'))
            else:
                extra = True
                submitted_diff.append("{}: {}".format(filename, 'EXTRA'))

        if missing or extra:
            diff_msg = (
                "Expected:\n\t{}\nSubmitted:\n\t{}".format(
                    '\n\t'.join(release_diff),
                    '\n\t'.join(submitted_diff),
                )
            )
            if missing and self.strict:
                self.fail(
                    "Assignment {} not submitted. "
                    "There are missing notebooks for the submission:\n{}"
                    "".format(self.coursedir.assignment_id, diff_msg)
                )
            else:
                self.log.warning(
                    "Possible missing notebooks and/or extra notebooks "
                    "submitted for assignment {}:\n{}"
                    "".format(self.coursedir.assignment_id, diff_msg)
                )

    def copy_files(self):
        self.init_release()

        dest_path = os.path.join(self.inbound_path, self.assignment_filename)
        if self.add_random_string:
            cache_path = os.path.join(self.cache_path, self.assignment_filename.rsplit('+', 1)[0])
        else:
            cache_path = os.path.join(self.cache_path, self.assignment_filename)

        logger = self.getLogger()
        logger.info("Source: %s", self.src_path)
        logger.info("Destination: %s", dest_path)

        # copy to the real location
        self.check_filename_diff()
        self.do_copy(self.src_path, dest_path)
        with open(os.path.join(dest_path, "timestamp.txt"), "w") as fh:
            fh.write(self.timestamp)
        self.set_perms(
            dest_path,
            fileperms=(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH),
            dirperms=(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH))

        if self.create_sakai_submission(dest_path) != 0:
            shutil.rmtree(dest_path, ignore_errors=True)
            self.fail("Cannot establish connection to Sakai. Submission was not successful.")

        # Make this 0777=ugo=rwx so the instructor can delete later. Hidden from other users by the timestamp.
        os.chmod(
            dest_path,
            S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH
        )

        # also copy to the cache
        if not os.path.isdir(self.cache_path):
            os.makedirs(self.cache_path)
        self.do_copy(self.src_path, cache_path)
        with open(os.path.join(cache_path, "timestamp.txt"), "w") as fh:
            fh.write(self.timestamp)

        logger.info("Submitted as: %s %s %s", self.coursedir.course_id, self.coursedir.assignment_id, str(self.timestamp))

    def create_sakai_submission(self, dest_path):
        base_url='https://sakai-dev.mci.edu'
        login_url = base_url + "/sakai-ws/soap/login?wsdl"
        script_url = base_url + "/sakai-ws/soap/sakai?wsdl"
        soap_url='/sakai-ws/soap'
        assignment_url = base_url + soap_url + "/assignments?wsdl"
        logger = self.getLogger()
        #https://sakai.mci4me.at/sakai-ws/soap/login?wsdl
        try:
            logger.info("%s", base_url)
            logger.info("%s", login_url)
            login_proxy = Client(login_url)
        except Exception as e:
            logger.info("Cannot establish connection to webservice: %s", e)
            return -1

        try:
            session_id = login_proxy.service.login(id='dd1337', pw='jDsG6Cy4wwWcZ4yZ9ZAA4uh')
            service_proxy = Client(assignment_url)
            course = os.environ['CONTEXT_ID']
            body = service_proxy.service.getAssignmentsForContext(session_id, course)
            root = ET.fromstring(body)
            for child in root:
                if child.attrib['title'] == self.coursedir.assignment_id:
                    assignment_id = child.attrib['id']
            user_id = os.environ['JUPYTERHUB_USER']

            submission_time = str(int(time.time() * 1000))
            attachment_name = user_id + "_" + self.coursedir.assignment_id + "_" + submission_time
            attachment_mime_type = "application/x-zip-compressed"
            zip_ret = shutil.make_archive(attachment_name, 'zip', dest_path)
            with open(zip_ret, 'rb') as file_in:
                bytes = file_in.read()
                encoded_string = base64.b64encode(bytes)

            os.remove(zip_ret)

            logger.info("Webservice call: %s, %s, %s, %s, %s, %s", session_id, course, assignment_id, user_id, submission_time, attachment_name)
            ret_val = service_proxy.service.createJupyterSubmission(session_id, course, assignment_id, user_id, submission_time, attachment_name, attachment_mime_type, encoded_string)
            login_proxy.service.logout(session_id)
            return 0
        except Exception as e:
            logger.info("Exception while sending data to Sakai: %s", e)
            login_proxy.service.logout(session_id)
            return -1
