CC = gcc
CFLAGS = -g
DEPS = rfc/rfc_protocol_ref.h
OBJ = ip_packet_monitor.o rfc/rfc_protocol_ref.o

%.o: %.c &(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<
	
ip_packet_monitor: $(OBJ)
	gcc $(CFLAGS) -o $@ $^