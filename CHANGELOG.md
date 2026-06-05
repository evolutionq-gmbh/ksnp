Changelog
=========

Version 0.4.0
-------------

* Fix a bug in hostname lookup for the stream example.
* Have the server ensure it only sends exact chunk-sized key data.
* Add further checks on stream parameters before serializing.
* Handle messages similar to events, adding a "none" variant.
* Add a field for user data to the stream and buffer structures.
* Make the C++ API public.
* Cloned ksnp_data to ksnp_cdata, which is its const variant used for key data
  chunks.
* Merge the data and size functions of ksnp_buffer to a method that returns
  ksnp_data.
* Add Python bindings.

Version 0.3.1
-------------

* Fix a bug in handling empty JSON payloads.

Version 0.3
-----------

* Change the buffer API to allow append to perform partial writes.
* When a client indicates EOF, the server will close the stream via an event.
* To indicate write EOF, write_data or flush_data may yield empty buffers.

Version 0.2
-----------

* Error messages are translated into error events, and do not return an error
  code.
* The client and server objects accept a direction parameter for
  close_connection, obsoleting then eed to provide an empty buffer to read_data.
* Message context accepts user-provided buffers. These buffers can be used to
  read and write data with one less copy. The client and server objects have a
  flush_data function to be used in lieu of write_data.
* Fix various bugs and check for more cases of invalid data.

Version 0.1
-----------

Initial release.
