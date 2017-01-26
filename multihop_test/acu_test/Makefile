BUILD_DIR = build

.PHONY: build clean

.ONESHELL:
build:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR)
	# TODO extract options correctly
	cmake -DCMAKE_BUILD_TYPE=Debug ..
	cmake --build . -- -j 4

# TODO add target to pull lib up

clean:
	$(RM) -rf $(BUILD_DIR)
