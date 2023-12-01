#!/bin/sh

USER=smfs
GROUP=smfs
UNAME=`uname`

echo "Creating the required user and group..."
if grep "^$GROUP:" /etc/group > /dev/null ; then
    :
else
    case $UNAME in
	*BSD)
	    pw groupadd -n $GROUP
	    ;;
	*)
	    groupadd $GROUP
    esac
fi
if grep "^$USER:" /etc/passwd > /dev/null ; then
    :
else
    case $UNAME in
	*BSD)
	    pw useradd -g $GROUP -n $USER -d /dev/null -s /dev/null
	    ;;
	*)
	    useradd -g $GROUP $USER -d /dev/null -s /dev/null
    esac
fi
echo "Done."

