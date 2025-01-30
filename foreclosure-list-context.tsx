import React, {createContext, type ReactNode, useContext, useEffect, useState} from 'react';
import {useNavigate} from "react-router-dom";

const BASE_URL = "http://localhost:5000";


type ApiContextType = {
  data: TaxForeclosure[];
  loading: boolean;
  error: string | null;
  getData: (url: string) => Promise<void>;
  postData: (url: string, data: any) => Promise<void>;
  resetError: () => void;
  listTaxForeclosures: () => TaxForeclosure[];
  fetchForeclosure: (id: string) => Promise<SingleTaxForeclosureResponse | undefined>;
  fetchForeclosuresByCounty: (county: string) => Promise<void>;
  fetchForeclosuresByStatus: (county: string) => Promise<void>;
  fetchForeclosuresByCountyAndStatus: (county: string, status: string) => Promise<void>;
  setDataDirectly: (newData: any) => void; // New method to set data
};

export type GoogleSignUpResponse = {
  request_uri: string;
  // Add any other expected properties if necessary
};

export type GoogleRequestResult = {
  request_processed: boolean;
  // Add any other expected properties if necessary
};

export type BasicPlanCheckout = {
  checkout: string;
  status: string;
};

export type DeveloperPlanCheckout = {
  checkout: string;
  status: string;
};

export type PaymentAccount = {
  id: string;
  user_id: string;
  stripe_customer_id: string;
};

export type User = {
  id: string;
  name: string;
  email: string;
  password: string;
  payment_account: PaymentAccount;
};

export type LoggedInUser = {
  success: boolean,
  message: string | User
}

export type AdditionalTaxForeclosureData = {
  id: string;
  tax_foreclosure_id: string;
  lot_size: string;
  assessed_value: number;
  delinquent:number;
  zoning_code: string;
  has_water: boolean;
  has_electric: boolean;
  has_sewage: boolean;
  legal_description: string;
  structure: string;
  year_built: string;
  condition: string;
  occupancy: string;
  street: string;
  city: string;
  state: string;
  zip: string;
  geometry:[];
  date_last_updated: any;
  lat: number;
  lng: number;
};



export type TaxForeclosure = {
  id: string;
  case_number: string;
  parcel_identification: string;
  reid_number: string;
  highest_bid: number;
  status: string;
  county: string;
  foreclosure_date: string;
  upset_bid_date: string;
  data:string;
  date_last_updated: any;
  additional_data: AdditionalTaxForeclosureData;
};

interface PropertyStatusProps {
  status: string;
  upsetBidDate?: string | null; // Optional, can be a string or null
  customMessage?: string; // Optional custom message
}

export type SingleTaxForeclosureResponse = {
  status: string;
  foreclosure: TaxForeclosure;
};

export type TaxForeclosuresResponse = {
  status: string;
  tax_foreclosures: TaxForeclosure[];
}

export const ForeclosureList = createContext<ApiContextType | undefined>(undefined);

// Custom hook to use the API context
export const useTaxForeclosureList = (): ApiContextType => {
  const context = useContext(ForeclosureList);
  if (!context) {
    throw new Error("useApi must be used within an ApiProvider");
  }
  return context;
};

// Fetch with timeout function
const fetchWithTimeout = (url: string, options: RequestInit, timeout = 60000) =>
  new Promise<Response>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Request timed out")), timeout);

  });

export const ForeclosureListProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [data, setData] = useState<TaxForeclosure[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {

    // You could check if the user is already logged in and redirect if needed
    console.log("list component loaded");

    const fetchData = async () => {
      const isLoggedIn = (await getData('/api/users/current_user')) as unknown as LoggedInUser;
      if (!isLoggedIn.success){
        console.log('you are not logged in')
        navigate('/login'); // Redirect to dashboard
      }
      // Fetch tax foreclosures
      const taxForeclosuresProperties = (await getData('/api/tax_foreclosure/list')) as unknown as TaxForeclosuresResponse;
      if (taxForeclosuresProperties) {
        if (taxForeclosuresProperties.tax_foreclosures){
          setData(taxForeclosuresProperties.tax_foreclosures);
          const tax_fore = taxForeclosuresProperties.tax_foreclosures;
          console.log("Tax Foreclosures:", tax_fore);
        }

      }
    };

    fetchData().then(r => {

    });
  }, []); // Dependencies are added to ensure this effect only runs once

  const getData = async (url: string): Promise<any> => {
    setLoading(true);
    setError(null);
    //setData(null); // Clear previous data for fresh request
    try {
      const response = await fetch(`${BASE_URL}${url}`, {
        method: 'GET',
        credentials: 'include',  // Include cookies in requests
      });

      return await response.json();  // Explicitly return result as Promise<any>
    } catch (err: any) {
      setError(err.message || "An error occurred");
      throw err;  // Re-throw error so calling function can handle it
    } finally {
      setLoading(false);
    }
  };

  const postData = async (url: string, data: any) => {
    setLoading(true);
    setError(null);
    try {


      const response = await fetch(`${BASE_URL}${url}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
        credentials: 'include',  // Include cookies in requests
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`Error ${response.status}: ${errorData.message || response.statusText}`);
      }

      return await response.json();  // Return data for use in calling function
    } catch (err: any) {
      setError(err.message || "An error occurred");
      throw err;  // Re-throw error so calling function can handle it
    } finally {
      setLoading(false);
    }
  };

  const listTaxForeclosures = (): TaxForeclosure[] => {
    return data as TaxForeclosure[];
  };

  const fetchForeclosure = async (id: string): Promise<SingleTaxForeclosureResponse | undefined> => {
    try {
      const response = await getData(`/api/tax_foreclosure/list_by_case_number/${id}`);
      return response as SingleTaxForeclosureResponse;

    } catch (error) {
      console.error("Error fetching foreclosure data:", error);
    }
  };

  const fetchForeclosuresByCounty = async (county: string): Promise<void> => {
    try {
      if (county === "None Selected") {
        const taxForeclosuresProperties = (await getData('/api/tax_foreclosure/list')) as unknown as TaxForeclosuresResponse;
        if (taxForeclosuresProperties) {
          setData(taxForeclosuresProperties.tax_foreclosures);
          const tax_fore = taxForeclosuresProperties.tax_foreclosures;
          return
        }
      }

      // Ensure the county parameter is valid
      if (!county) {
        console.warn("County parameter is required.");
        return;
      }

      // Fetch data from the API
      const response = await getData(`/api/tax_foreclosure/list_by_county/${county}`);

      // Ensure response contains expected data
      if (response && response.tax_foreclosures) {
        setData(response.tax_foreclosures); // Update state with fetched data
      } else {
        console.warn("No foreclosure data found for the selected county.");
        setData([]); // Clear state if no data is found
      }
    } catch (error) {
      console.error("Error fetching foreclosure data:", error);
      setData([]); // Clear state in case of an error
    }
  };

  const fetchForeclosuresByStatus = async (status: string): Promise<void> => {
    try {
      if (status === "None Selected") {
        const taxForeclosuresProperties = (await getData('/api/tax_foreclosure/list')) as unknown as TaxForeclosuresResponse;
        if (taxForeclosuresProperties) {
          setData(taxForeclosuresProperties.tax_foreclosures);
          const tax_fore = taxForeclosuresProperties.tax_foreclosures;
          return
        }
      }

      // Ensure the county parameter is valid
      if (!status) {
        console.warn("status parameter is required.");
        return;
      }

      // Fetch data from the API
      const response = await getData(`/api/tax_foreclosure/list_by_status/${status}`);

      // Ensure response contains expected data
      if (response && response.tax_foreclosures) {
        setData(response.tax_foreclosures); // Update state with fetched data
      } else {
        console.warn("No foreclosure data found for the selected status.");
        setData([]); // Clear state if no data is found
      }
    } catch (error) {
      console.error("Error fetching foreclosure data:", error);
      setData([]); // Clear state in case of an error
    }
  };

  const fetchForeclosuresByCountyAndStatus = async (county: string, status: string): Promise<void> =>{
    try {
      // Ensure the county parameter is valid
      if (!status && !county) {
        console.warn("status and county parameter is required.");
        return;
      }

      // Fetch data from the API
      const response = await getData(`/api/tax_foreclosure/list_by_county_and_status/${county}/${status}`);

      // Ensure response contains expected data
      if (response && response.tax_foreclosures) {
        setData(response.tax_foreclosures); // Update state with fetched data
      } else {
        console.warn("No foreclosure data found for the selected status.");
        setData([]); // Clear state if no data is found
      }
    } catch (error) {
      console.error("Error fetching foreclosure data:", error);
      setData([]); // Clear state in case of an error
    }
  };

  const setDataDirectly = (newData: any) => {
    setData(newData);
  };

  const resetError = () => setError(null);

  return (
    <ForeclosureList.Provider value={{ data, loading, error, getData, postData, resetError, listTaxForeclosures, fetchForeclosure, fetchForeclosuresByCounty, fetchForeclosuresByStatus, fetchForeclosuresByCountyAndStatus, setDataDirectly}}>
      {children}
    </ForeclosureList.Provider>
  );
};
