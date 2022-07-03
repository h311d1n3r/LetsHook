echo "Setting up environment..."
eval "$(cmd "/C prepare_env.bat")"
echo "Done !"
echo "Starting build process..."
make
echo "Done !"
echo "Enjoy using the library !"