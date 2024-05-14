import express from 'express';
import axios from 'axios';
import cryptoJs from 'crypto-js';
import storage from 'node-persist';
import bodyParser from 'body-parser';
import 'dotenv/config';


const app = express();
const port = 3000;
app.use(bodyParser.json());
storage.init();

const baseUrl = process.env.BASEURL;

const clientId = process.env.CLIENTID;
const clientSecret = process.env.CLIENTSEC;
const username = process.env.USERNAME;
const password = process.env.USERPWD;

const clientIdAMZ = process.env.A_CLIENTID;
const clientSecretAMZ = process.env.A_CLIENTSEC;
const usernameAMZ = process.env.A_USERNAME;
const passwordAMZ = process.env.A_USERPWD + "#";

//  include timestamp in logs
console.log = (function () {
    var console_log = console.log;
    var timeStart = new Date().getTime();

    return function () {
        var delta = new Date().getTime() - timeStart;
        var args = [];
        args.push((delta / 1000).toFixed(2) + ':');
        for (var i = 0; i < arguments.length; i++) {
            args.push(arguments[i]);
        }
        console_log.apply(console, args);
    };
})();


//  Get Authorization Code
async function getAuthorizationCode(baseOAuthUrl, clientId, username, password) {
    const verifyEndpoint = `${baseOAuthUrl}/oauth2/verify`;

    try {
        const response = await axios.post(verifyEndpoint, {
            clientId,
            username,
            password
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const authorizationCode = response.data.authorizationCode;
        // console.log(authorizationCode);
        return authorizationCode;
    } catch (error) {
        console.error('Error getting authorization code:', error.message);
        return error.data || error;
    }
}

// Get Bearer Token
async function getBearerToken(baseOAuthUrl, clientId, clientSecret, authorizationCode) {
    const tokenEndpoint = `${baseOAuthUrl}/oauth2/token`;

    try {
        const response = await axios.post(tokenEndpoint, {
            clientId,
            clientSecret,
            authorizationCode
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const bearerToken = response.data.token;
        // console.log(bearerToken);
        return bearerToken;
    } catch (error) {
        console.error('Error getting bearer token:', error.message);
        return error.data || error;

    }
}


// Generate Signature
function generateSignature(method, apiUrl, requestBody) {

    let absApiUrl = apiUrl;

    let sortObject = (object) => {
        if (object instanceof Array) {
            var sortedObj = [],
                keys = Object.keys(object);
        }
        else {
            sortedObj = {},
                keys = Object.keys(object);
        }

        keys.sort(function (key1, key2) {
            if (key1 < key2) return -1;
            if (key1 > key2) return 1;
            return 0;
        });

        for (var index in keys) {
            var key = keys[index];
            if (typeof object[key] == 'object' && !!object[key]) {
                if ((object[key] instanceof Array)) {
                    sortedObj[key] = sortObject(object[key]);
                }
                sortedObj[key] = sortObject(object[key]);
            } else {
                sortedObj[key] = object[key];
            }
        }
        return sortedObj;
    }

    let sortQueryParams = () => {
        let url = absApiUrl.split('?'),
            baseUrl = url[0],
            queryParam = url[1].split('&');

        absApiUrl = baseUrl + '?' + queryParam.sort().join('&');

        return fixedEncodeURIComponent(absApiUrl);
    }

    let getConcatenateBaseString = () => {
        let baseArray = [];
        baseArray.push(method.toUpperCase());

        if (absApiUrl.indexOf('?') >= 0) {
            baseArray.push(sortQueryParams());
        } else {
            baseArray.push(fixedEncodeURIComponent(absApiUrl));
        }
        if (requestBody) {
            baseArray.push(fixedEncodeURIComponent(JSON.stringify(sortObject(requestBody))));
        }

        return baseArray.join('&');
    }

    let fixedEncodeURIComponent = (str) => {
        return encodeURIComponent(str).replace(/[!'()*]/g, function (c) {
            return '%' + c.charCodeAt(0).toString(16).toUpperCase();
        });
    }

    const signature = cryptoJs.HmacSHA512(getConcatenateBaseString(), clientSecret);
    return signature;
}


app.get('/', async (req, res) => {

    const token = await storage.getItem('token');

    if (token) {
        res.send('Hello World!');

    } else {
        res.send('Not logged in');

    }
})

app.get('/get-auth', async (req, res) => {

    const authorizationCode = await getAuthorizationCode(baseUrl, clientId, username, password);
    console.log('Authorization Code:', authorizationCode);


    const bearerToken = await getBearerToken(baseUrl, clientId, clientSecret, authorizationCode);
    console.log('Bearer Token:', bearerToken);


    if (bearerToken?.message || !bearerToken) {
        res.send({ "error": bearerToken?.message || "Didn't get token", });
    } else {
        await storage.setItem('token', bearerToken);
        res.send({ "success": true });
    }
})

app.get('/get-auth-amz', async (req, res) => {

    console.log("NewIds:", clientIdAMZ, usernameAMZ, passwordAMZ, clientSecretAMZ);
    const authorizationCode = await getAuthorizationCode(baseUrl, clientIdAMZ, usernameAMZ, passwordAMZ);
    console.log('Authorization Code:', authorizationCode);


    const bearerToken = await getBearerToken(baseUrl, clientIdAMZ, clientSecretAMZ, authorizationCode);
    console.log('Bearer Token:', bearerToken);


    if (bearerToken?.message || !bearerToken) {
        res.send({ "error": bearerToken?.message || "Didn't get token", });
    } else {
        await storage.setItem('amzToken', bearerToken);
        res.send({ "success": true });
    }
})

app.get('/store-categories', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {

        const categoriesEndpoint = `${baseUrl}/rest/v3/catalog/categories/`;
        const signature = generateSignature('get', categoriesEndpoint, null);
        const dateAtClient = new Date().toISOString();

        let responseText;
        try {
            const response = await axios.get(categoriesEndpoint, {
                headers: {
                    'Content-Type': 'application/json',
                    'dateAtClient': dateAtClient,
                    'signature': signature,
                    'Authorization': `Bearer ${bearerToken}`

                }
            });
            responseText = response?.data;
        } catch (error) {
            console.error('Error getting bearer token:', error.message);
            responseText = error;
        }
        if (responseText?.message) {
            res.send({ "error": responseText.message });
        } else {
            await storage.setItem('category_list', responseText);
            res.send(responseText);
        }
    }
})

app.get('/store-categories-amz', async (req, res) => {
    const bearerToken = await storage.getItem('amzToken');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {

        const categoriesEndpoint = `${baseUrl}/rest/v3/catalog/categories/`;
        const signature = generateSignature('get', categoriesEndpoint, null);
        const dateAtClient = new Date().toISOString();

        let responseText;
        try {
            const response = await axios.get(categoriesEndpoint, {
                headers: {
                    'Content-Type': 'application/json',
                    'dateAtClient': dateAtClient,
                    'signature': signature,
                    'Authorization': `Bearer ${bearerToken}`

                }
            });
            responseText = response?.data;
        } catch (error) {
            console.error('Error getting bearer token:', error.message);
            responseText = error;
        }
        if (responseText?.message) {
            res.send({ "error": responseText.message });
        } else {
            await storage.setItem('category_list_amz', responseText);
            res.send(responseText);
        }
    }
})

app.get('/store-categories/:id', async (req, res) => {
    const id = req.params.id;

    const bearerToken = await storage.getItem('token');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {

        const categoriesEndpoint = `${baseUrl}/rest/v3/catalog/categories/${id}`;
        const signature = generateSignature('get', categoriesEndpoint, null);
        const dateAtClient = new Date().toISOString();

        let responseText;
        try {
            const response = await axios.get(categoriesEndpoint, {
                headers: {
                    'Content-Type': 'application/json',
                    'dateAtClient': dateAtClient,
                    'signature': signature,
                    'Authorization': `Bearer ${bearerToken}`

                }
            });
            responseText = response?.data;
        } catch (error) {
            console.error('Error getting bearer token:', error.message);
            responseText = error;
        }
        if (responseText?.message) {
            res.send({ "error": responseText.message });
        } else {
            await storage.setItem('c' + id, responseText);
            res.send(responseText);
        }
    }
})

app.get('/store-product-list', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {

        const categoryList = await storage.getItem('category_list');
        let count = 0;
        if (Array.isArray(categoryList)) {
            let productList = [];
            await Promise.all(
                categoryList.map(async (category) => {

                    const endpoint = `${baseUrl}/rest/v3/catalog/categories/${category.id}/products`;
                    const signature = generateSignature('get', endpoint, null);
                    const dateAtClient = new Date().toISOString();

                    let responseText;
                    try {
                        const response = await axios.get(endpoint, {
                            headers: {
                                'Content-Type': 'application/json',
                                'dateAtClient': dateAtClient,
                                'signature': signature,
                                'Authorization': `Bearer ${bearerToken}`

                            }
                        });
                        responseText = response?.data;
                    } catch (error) {
                        console.error('Error getting bearer token:', error.message);
                        responseText = error;
                    }
                    if (!responseText?.message) {
                        productList.push(responseText?.products);
                        count += 1;
                    }

                })
            )
            if (productList?.length > 0) {
                await storage.setItem("product_list", productList.flat());
            }
        } else if (categoryList?.id) {
            const endpoint = `${baseUrl}/rest/v3/catalog/categories/${categoryList.id}/products`;
            const signature = generateSignature('get', endpoint, null);
            const dateAtClient = new Date().toISOString();

            let responseText;
            try {
                const response = await axios.get(endpoint, {
                    headers: {
                        'Content-Type': 'application/json',
                        'dateAtClient': dateAtClient,
                        'signature': signature,
                        'Authorization': `Bearer ${bearerToken}`

                    }
                });
                responseText = response?.data;
            } catch (error) {
                console.error('Error getting bearer token:', error.message);
                responseText = error;
            }
            if (!responseText?.message) {
                await storage.setItem("product_list", responseText?.products);
                await storage.setItem("c" + categoryList?.id + "list", responseText)
                count += 1;
            }
        }
        res.send({ "message": `Added ${count} products` });
    }


})

app.get('/store-product-list-amz', async (req, res) => {
    const bearerToken = await storage.getItem('amzToken');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {

        const categoryList = await storage.getItem('category_list_amz');
        let count = 0;
        if (Array.isArray(categoryList)) {
            let productList = [];
            await Promise.all(
                categoryList.map(async (category) => {

                    const endpoint = `${baseUrl}/rest/v3/catalog/categories/${category.id}/products`;
                    const signature = generateSignature('get', endpoint, null);
                    const dateAtClient = new Date().toISOString();

                    let responseText;
                    try {
                        const response = await axios.get(endpoint, {
                            headers: {
                                'Content-Type': 'application/json',
                                'dateAtClient': dateAtClient,
                                'signature': signature,
                                'Authorization': `Bearer ${bearerToken}`

                            }
                        });
                        responseText = response?.data;
                    } catch (error) {
                        console.error('Error getting bearer token:', error.message);
                        responseText = error;
                    }
                    if (!responseText?.message) {
                        productList.push(responseText?.products);
                        count += 1;
                    }

                })
            )
            if (productList?.length > 0) {
                await storage.setItem("product_list_amz", productList.flat());
            }
        } else if (categoryList?.id) {
            const endpoint = `${baseUrl}/rest/v3/catalog/categories/${categoryList.id}/products`;
            const signature = generateSignature('get', endpoint, null);
            const dateAtClient = new Date().toISOString();

            let responseText;
            try {
                const response = await axios.get(endpoint, {
                    headers: {
                        'Content-Type': 'application/json',
                        'dateAtClient': dateAtClient,
                        'signature': signature,
                        'Authorization': `Bearer ${bearerToken}`

                    }
                });
                responseText = response?.data;
            } catch (error) {
                console.error('Error getting bearer token:', error.message);
                responseText = error;
            }
            if (!responseText?.message) {
                await storage.setItem("product_list_amz", responseText?.products);
                await storage.setItem("c" + categoryList?.id + "list_amz", responseText)
                count += 1;
            }
        }
        res.send({ "message": `Added ${count} products` });
    }


})

app.get('/store-product-data', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {

        const productList = await storage.getItem('product_list');
        // console.log(productList);
        let count = 0;
        if (Array.isArray(productList)) {
            await Promise.all(
                productList.map(async (product) => {

                    const endpoint = `${baseUrl}/rest/v3/catalog/products/${product.sku}`;
                    const signature = generateSignature('get', endpoint, null);
                    const dateAtClient = new Date().toISOString();

                    let responseText;
                    try {
                        const response = await axios.get(endpoint, {
                            headers: {
                                'Content-Type': 'application/json',
                                'dateAtClient': dateAtClient,
                                'signature': signature,
                                'Authorization': `Bearer ${bearerToken}`

                            }
                        });
                        responseText = response?.data;
                    } catch (error) {
                        console.error('Error getting bearer token:', error.message);
                        responseText = error;
                    }
                    if (!responseText?.message) {
                        await storage.setItem(product.url, responseText);
                        count += 1;
                    }


                })
            )
        }
        res.send({ "message": `Added ${count} products` });
    }


})

app.get('/store-product-data-amz', async (req, res) => {
    const bearerToken = await storage.getItem('amzToken');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {

        const productList = await storage.getItem('product_list_amz');
        // console.log(productList);
        let count = 0;
        if (Array.isArray(productList)) {
            await Promise.all(
                productList.map(async (product) => {

                    const endpoint = `${baseUrl}/rest/v3/catalog/products/${product.sku}`;
                    const signature = generateSignature('get', endpoint, null);
                    const dateAtClient = new Date().toISOString();

                    let responseText;
                    try {
                        const response = await axios.get(endpoint, {
                            headers: {
                                'Content-Type': 'application/json',
                                'dateAtClient': dateAtClient,
                                'signature': signature,
                                'Authorization': `Bearer ${bearerToken}`

                            }
                        });
                        responseText = response?.data;
                    } catch (error) {
                        console.error('Error getting bearer token:', error.message);
                        responseText = error;
                    }
                    if (!responseText?.message) {
                        await storage.setItem(product.url, responseText);
                        count += 1;
                    }


                })
            )
        }
        res.send({ "message": `Added ${count} products` });
    }


})

app.get('/get-categories', async (req, res) => {

    const categoryList = await storage.getItem("category_list");

    res.send(categoryList);


})

app.get('/get-categories/:id', async (req, res) => {
    const id = req.params.id;

    const categoryList = await storage.getItem("c" + id);
    res.send(categoryList);

})

app.get('/get-category-products/:id', async (req, res) => {
    const id = req.params.id;

    const categoryList = await storage.getItem("c" + id + "list");
    res.send(categoryList);

})

app.get('/get-product-list', async (req, res) => {

    const productList = await storage.getItem("product_list");
    const productListAmz = await storage.getItem("product_list_amz");

    res.send([productList, productListAmz]);


})

app.get('/get-product-list-amz', async (req, res) => {

    const productList = await storage.getItem("product_list_amz");

    res.send(productList);


})

app.get('/get-product/:url', async (req, res) => {
    const url = req.params.url;
    const product = await storage.getItem(url);
    res.send(product);

})


app.post('/create-order', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    const amzToken = await storage.getItem('amzToken');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {
        let orderData = req?.body;
        try {

            let amazonGiftCards = { ...orderData, products: orderData?.amz_products || [], payments: orderData?.amz_payments || [] }

            let normalGiftCards = { ...orderData, products: orderData?.products, payments: orderData?.payments }
            console.log(normalGiftCards, "normalGiftcards object");
            // Extract data from the request body
            const endpoint = `${baseUrl}/rest/v3/orders`;
            const signature = generateSignature('post', endpoint, normalGiftCards);
            const dateAtClient = new Date().toISOString();
            // Make a POST request to the specified endpoint
            const response = await axios.post(endpoint, normalGiftCards, {
                headers: {
                    'Content-Type': 'application/json',
                    'dateAtClient': dateAtClient,
                    'signature': signature,
                    'Authorization': `Bearer ${bearerToken}`
                }
            });

            let amzResponse = {}

            if (amazonGiftCards?.products?.length > 0) {
                const signature = generateSignature('post', endpoint, amazonGiftCards);
                const dateAtClient = new Date().toISOString();
                amzResponse = await axios.post(endpoint, amazonGiftCards, {
                    headers: {
                        'Content-Type': 'application/json',
                        'dateAtClient': dateAtClient,
                        'signature': signature,
                        'Authorization': `Bearer ${amzToken}`
                    }
                });
            }


            // Send the response from the Woohoo API back to the client
            res.json({ ...response?.data, amz_details: amzResponse });
        } catch (error) {


            // Handle errors
            console.error('Error creating order:', error.message);
            res.status(500).json({ error: error?.response?.data || 'Internal Server Error', message: error?.message, errorCode: error?.code });
        }
    }
});

app.post('/reverse-order', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {
        let orderData = req?.body;
        try {
            // Extract data from the request body
            const endpoint = `${baseUrl}/rest/v3/orders/reverse`;
            // console.log("data", orderData);
            const signature = generateSignature('post', endpoint, orderData);
            const dateAtClient = new Date().toISOString();
            // Make a POST request to the specified endpoint
            const response = await axios.post(endpoint, orderData, {
                headers: {
                    'Content-Type': 'application/json',
                    'dateAtClient': dateAtClient,
                    'signature': signature,
                    'Authorization': `Bearer ${bearerToken}`
                }
            });

            // Send the response from the Woohoo API back to the client
            res.json(response?.data);
        } catch (error) {
            // Handle errors
            console.error('Error creating order:', error.message);
            res.status(500).json({ error: error?.response?.data || 'Internal Server Error', message: error?.message, errorCode: error?.code });
        }
    }
});

app.get('/get-order/:id', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    const id = req?.params?.id;

    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {
        try {
            // Extract data from the request body
            const endpoint = `${baseUrl}/rest/v3/orders/${id}`;
            const signature = generateSignature('get', endpoint, null);
            const dateAtClient = new Date().toISOString();
            // Make a POST request to the specified endpoint
            const response = await axios.get(endpoint, {
                headers: {
                    'Content-Type': 'application/json',
                    'dateAtClient': dateAtClient,
                    'signature': signature,
                    'Authorization': `Bearer ${bearerToken}`
                }
            });

            // Send the response from the Woohoo API back to the client
            res.json(response?.data);
        } catch (error) {
            // Handle errors
            console.error('Error creating order:', error.message);
            res.status(500).json({ error: error?.response?.data || 'Internal Server Error', message: error?.message, errorCode: error?.code });
        }
    }
});

app.get('/get-order-status/:refno', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    const refno = req?.params?.refno;

    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {
        try {
            // Extract data from the request body
            const endpoint = `${baseUrl}/rest/v3/orders/${refno}/status`;
            const signature = generateSignature('get', endpoint, null);
            const dateAtClient = new Date().toISOString();
            // Make a POST request to the specified endpoint
            const response = await axios.get(endpoint, {
                headers: {
                    'Content-Type': 'application/json',
                    'dateAtClient': dateAtClient,
                    'signature': signature,
                    'Authorization': `Bearer ${bearerToken}`
                }
            });

            // Send the response from the Woohoo API back to the client
            res.json(response?.data);
        } catch (error) {
            // Handle errors
            console.error('Error creating order:', error.message);
            res.status(500).json({ error: error?.response?.data || 'Internal Server Error', message: error?.message, errorCode: error?.code });
        }
    }
});

app.get('/get-card/:id', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    const id = req?.params?.id;

    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {
        try {
            // Extract data from the request body
            const endpoint = `${baseUrl}/rest/v3/order/${id}/cards/?offset=0&limit=10`;
            const signature = generateSignature('get', endpoint, null);
            const dateAtClient = new Date().toISOString();
            // Make a POST request to the specified endpoint
            const response = await axios.get(endpoint, {
                headers: {
                    'Content-Type': 'application/json',
                    'dateAtClient': dateAtClient,
                    'signature': signature,
                    'Authorization': `Bearer ${bearerToken}`
                }
            });

            // Send the response from the Woohoo API back to the client
            res.json(response?.data);
        } catch (error) {
            // Handle errors
            console.error('Error creating order:', error.message);
            res.status(500).json({ error: error?.response?.data || 'Internal Server Error', message: error?.message, errorCode: error?.code });
        }
    }
});

app.get('/send-products-hasura', async (req, res) => {

    const productList = await storage.getItem("product_list");

    // Prepare the data for hasura
    const finalData = await Promise.all(productList.map(async (product) => {
        const prodData = await storage.getItem(product?.url);
        return {
            "min_price": product?.minPrice,
            "max_price": product?.maxPrice,
            "slug": product?.url,


            "sku": prodData?.sku,
            "product_id": prodData?.id,
            "brand_name": prodData?.brandName,
            "card_behaviour": prodData?.cardBehaviour,
            "categories": prodData?.categories,
            "convenience_charges": prodData?.convenience_charges,
            "cpg": prodData?.cpg,
            "currency": prodData?.currency,
            "custom_themes_available": prodData?.customThemesAvailable,
            "description": prodData?.description,
            "discounts": prodData?.discounts,
            "eta_message": prodData?.etaMessage,
            "expiry": prodData?.expiry,
            "giftcard_updated": prodData?.updatedAt,
            "giftcard_created_at": prodData?.createdAt,
            "handling_charges": prodData?.handlingCharges,
            "images": prodData?.images,
            "kyc_enabled": prodData?.kycEnabled,
            "meta_information": prodData?.metaInformation,
            "name": prodData?.name,
            "payout": prodData?.payout,
            "price": prodData?.price,
            "related_products": prodData?.relatedProducts,
            "reload_card_number": prodData?.reloadCardNumber,
            "scheduling_enabled": prodData?.schedulingEnabled,
            "tnc": prodData?.tnc,
            "type": prodData?.type
        }
    }));
    res.status(200).json(finalData);

});

app.get('/send-products-hasura-amz', async (req, res) => {

    const productList = await storage.getItem("product_list_amz");

    // Prepare the data for hasura
    const finalData = await Promise.all(productList.map(async (product) => {
        const prodData = await storage.getItem(product?.url);
        return {
            "min_price": product?.minPrice,
            "max_price": product?.maxPrice,
            "slug": product?.url,


            "sku": prodData?.sku,
            "product_id": prodData?.id,
            "brand_name": prodData?.brandName,
            "card_behaviour": prodData?.cardBehaviour,
            "categories": prodData?.categories,
            "convenience_charges": prodData?.convenience_charges,
            "cpg": prodData?.cpg,
            "currency": prodData?.currency,
            "custom_themes_available": prodData?.customThemesAvailable,
            "description": prodData?.description,
            "discounts": prodData?.discounts,
            "eta_message": prodData?.etaMessage,
            "expiry": prodData?.expiry,
            "giftcard_updated": prodData?.updatedAt,
            "giftcard_created_at": prodData?.createdAt,
            "handling_charges": prodData?.handlingCharges,
            "images": prodData?.images,
            "kyc_enabled": prodData?.kycEnabled,
            "meta_information": prodData?.metaInformation,
            "name": prodData?.name,
            "payout": prodData?.payout,
            "price": prodData?.price,
            "related_products": prodData?.relatedProducts,
            "reload_card_number": prodData?.reloadCardNumber,
            "scheduling_enabled": prodData?.schedulingEnabled,
            "tnc": prodData?.tnc,
            "type": prodData?.type
        }
    }));
    res.status(200).json(finalData);

});

app.listen(port, () => {
    console.log(`App listening on port ${port}`)
})
