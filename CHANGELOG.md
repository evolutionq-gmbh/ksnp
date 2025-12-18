Changelog
=========

Version 0.2
-----------

* Error messages are translated into error events, and do not return an error
  code.
* The client and server objects accept a direction parameter for
  close_connection, obsoleting then eed to provide an empty buffer to read_data.
* Message context accepts user-provided buffers. These buffers can be used to
  read and write data with one less copy. The client and server objects have a
  flush_data function to be used in lieu of write_data.
* Fix various bugs.

Version 0.1
-----------

Initial release.
