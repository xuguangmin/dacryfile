#
#

all:  
	@echo "Makeing required objects..."
	@cd linux && make all

	@echo "Makeing parasite"
	@cd src && make all
	@cd obj && make all

	@echo "Makeing utils..."
	@cd util && make all

	@echo "Installing to bin..."
	@cp util/inject util/encrypt bin 

clean:
	@cd linux && make clean
	@cd util && make clean
	@cd src && make clean
	@cd obj && make clean
	/bin/rm -rf  demo/host* bin/*
