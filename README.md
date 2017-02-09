# elfloader
load so file into current memory space and run function

# run

	# create example, hello.so 
	make -f makefile.hello
	
	# make elfloader
	make
	
	# run function main1 in hello.so
	./elfloader ./hello.so main1
	

elemeta47 at gmail dot com