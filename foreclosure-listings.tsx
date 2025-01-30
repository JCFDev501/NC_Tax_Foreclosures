import {useTaxForeclosureList} from "#/context/foreclosure-list-context";
import React, {useMemo, useRef, useState} from "react";
import type {TaxForeclosure} from "#/context/api-context";
import {Link} from "react-router-dom";
import ForeclosureCard from "#/components/foreclosure-card";
import SearchBar from "#/components/search-bar";
import ForeclosureOverallViewer from "#/components/gis/foreclosure-overall-viewer";

function ForeclosureListings(props:{}) {
  const {
    loading,
    error,
    data,
    setDataDirectly
  } = useTaxForeclosureList(); // Access API context
  const [sortedForeclosures, setSortedForeclosures] = useState<TaxForeclosure[]>([]);
  const [activeSort, setActiveSort] = useState<string>(""); // Track active button
  const map = useRef<HTMLArcgisMapElement>();

  const foreclosuresWithAdditionalData = useMemo(() =>
    data.filter((value)=> value.additional_data !== null)
  , [data]);


  // Functions to sort by price
  const sortByLowestPrice = () => {
    if (!loading && !error) {
      const sorted = [...data].sort((a, b) => a.highest_bid - b.highest_bid);
      console.log(sorted);
      setDataDirectly(sorted);
    }
  };

  const sortByHighestPrice = () => {
    if (!loading && !error) {
      const sorted = [...data].sort((a, b) => b.highest_bid - a.highest_bid);
      console.log(sorted);
      setDataDirectly(sorted);
    }
  };

  const sortByMostRecentDate = () => {
    if (!loading && !error) {
      const sorted = [...data].sort((a, b) => {
        const dateA = new Date(a.foreclosure_date).getTime();
        const dateB = new Date(b.foreclosure_date).getTime();
        return dateB - dateA; // Sort in descending order (most recent first)
      });
      console.log(sorted);
      setDataDirectly(sorted);
    }
  };

  const handleSortClick = (sortType: string, sortFunction: () => void) => {
    setActiveSort(sortType); // Update active button state
    sortFunction(); // Call the respective sort function
  };



  return (
    <div className="flex flex-1 h-[92%] flex-col font-monument">
      {/* Search Bar */}
      <div className="border-b">
        <SearchBar />
      </div>

      {/* Main Content */}
      <div className="flex flex-1 h-0">
        {/*Card section*/}
        <div className=" flex flex-col w-full max-h-full  overflow-auto ">
          {/* Header and Sort Bar */}
          <div className="md:flex-row flex flex-col justify-between items-center p-4">
            <h2 className="text-lg font-semibold">
              {
                !loading && !error
                  ? data?.filter((foreclosure) => foreclosure.additional_data).length
                  : 0
              } places found
            </h2>
            <div className="flex items-center font-bold space-x-2">
              <span className="text-gray-600">Sort by:</span>
              <button
                onClick={() => handleSortClick("mostRecent", sortByMostRecentDate)}
                className={`border px-3 py-1 ${
                  activeSort === "mostRecent" ? "text-blue-500 border-blue-500" : "text-gray-600"
                } hover:text-blue-500 hover:border-blue-500`}
              >
                Most recent
              </button>
              {/* Lowest price button */}
              <button
                onClick={() => handleSortClick("lowestPrice", sortByLowestPrice)}
                className={`border px-3 py-1 ${
                  activeSort === "lowestPrice" ? "text-blue-500 border-blue-500" : "text-gray-600"
                } hover:text-blue-500 hover:border-blue-500`}
              >
                Lowest price
              </button>

              {/* Most recent button */}
              <button
                onClick={() => handleSortClick("highestPrice", sortByHighestPrice)}
                className={`border px-3 py-1 ${
                  activeSort === "highestPrice" ? "text-blue-500 border-blue-500" : "text-gray-600"
                } hover:text-blue-500 hover:border-blue-500`}
              >
                Highest price
              </button>

              {/*/!* More button *!/*/}
              {/*<button*/}
              {/*  className={`border px-3 py-1 ${*/}
              {/*    activeSort === "more" ? "text-blue-500 border-blue-500" : "text-gray-600"*/}
              {/*  } hover:text-blue-500 hover:border-blue-500`}*/}
              {/*  onClick={() => handleSortClick("more", () => console.log("More clicked"))}*/}
              {/*>*/}
              {/*  More*/}
              {/*</button>*/}
            </div>

          </div>


          {/* Cards Section */}
          <div
            className=" p-4"
          >
            {/* Cards Grid */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
              {!loading && !error && data.length > 0 ? (
                data
                  .filter((foreclosure) => foreclosure.additional_data) // Filter only cards with additional data
                  .sort((a, b) => {
                    // Push 'N/A' to the bottom
                    const highestBidA = a.highest_bid === 0 ? 1 : 0;
                    const highestBidB = b.highest_bid === 0 ? 1 : 0;
                    return highestBidA - highestBidB;
                  })
                  .map((foreclosure) => (
                    <Link
                      key={foreclosure.id}
                      className="bg-white hover:shadow-xl transition-shadow overflow-hidden"
                      to = {`/details/${foreclosure.case_number}`}
                    >
                      <ForeclosureCard foreclosure={foreclosure} />
                    </Link>
                  ))
              ) : (
                <p className="text-gray-600">
                  {loading ? "Loading..." : "No tax foreclosure data available."}
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Map Section */}
        <div className="bg-white hidden md:block  h-full w-full">
          <ForeclosureOverallViewer foreclosures={foreclosuresWithAdditionalData}/>
      </div>
      </div>
    </div>
  );
};

export default ForeclosureListings;
