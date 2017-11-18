##########################################################################
#
#    Mp4Info Program
#
#    (c) 2002-2008 Axiomatic Systems, LLC
#
##########################################################################
all: mp4iframeindex

##########################################################################
# includes
##########################################################################
include $(BUILD_ROOT)/Makefiles/Lib.exp

##########################################################################
# targets
##########################################################################
TARGET_SOURCES = Mp4IframeIndex.cpp

##########################################################################
# make path
##########################################################################
VPATH += $(SOURCE_ROOT)/Apps/Mp4IframeIndex

##########################################################################
# includes
##########################################################################
include $(BUILD_ROOT)/Makefiles/Rules.mak

##########################################################################
# rules
##########################################################################
mp4iframeindex: $(TARGET_OBJECTS) $(TARGET_LIBRARY_FILES)
	$(LINK) $(TARGET_OBJECTS) -o $@ $(LINK_LIBRARIES)

