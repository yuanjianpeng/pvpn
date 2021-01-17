bin := pvpn

srcs := $(wildcard *.c)
objs := $(srcs:%.c=obj/%.o)

__dummy := $(shell mkdir -p obj/)

all: $(bin);

$(bin): $(objs)
	$(CC) -o $@ $^

obj/%.o: %.c
	$(CC) -o $@ -c $<

ifneq ($(MAKECMDGOALS),clean)
sinclude $(srcs:%.c=obj/%.d)
endif

obj/%.d: %.c
	@$(CC) -MM $(CPPFLAGS) $< | sed 's#\($*\)\.o[ :]*#obj/\1.o $@ : #g' > $@

.PHONY: clean
clean:
	rm -rf $(bin) obj/

