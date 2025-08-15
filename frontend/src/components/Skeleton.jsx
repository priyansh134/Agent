// Diplay the loading UI 
import React from 'react'

const Skeleton = () => {
    return (
        <div role="status" className="w-auto m-2 my-5 animate-pulse ">
            <div className="h-6 bg-gray-200 rounded-lg dark:bg-gray-300 w-full mb-4"></div>
            <div className="h-6 bg-gray-200 rounded-lg dark:bg-gray-300 w-full mb-4"></div>
            <div className="h-6 bg-gray-200 rounded-lg dark:bg-gray-300 w-full mb-4"></div>
            <div className="h-6 bg-gray-200 rounded-lg dark:bg-gray-300 w-full mb-4"></div>
            <div className="h-6 bg-gray-200 rounded-lg dark:bg-gray-300 w-full"></div>
            <span className="sr-only">Loading...</span>
        </div>
    )
}

export default Skeleton