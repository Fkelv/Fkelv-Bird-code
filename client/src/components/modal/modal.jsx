export const Modal = ({ isModalOpen, children, closeModal }) => {
  return (
    <>
      {isModalOpen && (
        <div className="fixed top-0 left-0 w-full h-full flex items-center justify-center z-50">
          <div
            className="fixed top-0 left-0 w-full h-full bg-black opacity-50"
            onClick={closeModal}
          ></div>
          <div className="bg-white p-6 rounded-lg z-10 relative">
            <button
              className="absolute top-2 right-2 text-gray-600 hover:text-gray-800"
              onClick={closeModal}
            >
              &times;
            </button>
            {children}
          </div>
        </div>
      )}
    </>
  );
};
