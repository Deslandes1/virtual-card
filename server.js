 const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// SMTP transporter setup
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

// Helper: hash PIN
function hashPin(pin) {
    return crypto.createHash('sha256').update(pin).digest('hex');
}

// Helper: generate 6-digit code
function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper: dummy card number
function generateCardNumber() {
    return `411111111111${Math.floor(Math.random() * 10000).toString().padStart(4, '0')}`;
}

// ============= CARD MANAGEMENT =============

// Create new virtual card (with email and PIN)
app.post('/api/card/create', async (req, res) => {
    const { userId, cardHolder, email, pin } = req.body;
    if (!userId || !cardHolder || !email || !pin) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const expiryMonth = Math.floor(Math.random() * 12) + 1;
    const expiryYear = 2028;
    const cvv = Math.floor(100 + Math.random() * 900).toString();
    const cardNumber = generateCardNumber();
    const masked = `**** **** **** ${cardNumber.slice(-4)}`;
    const pinHash = hashPin(pin);

    const { data, error } = await supabase
        .from('cards')
        .insert({
            user_id: userId,
            card_number: masked,
            card_holder: cardHolder,
            email: email,
            expiry_month: expiryMonth,
            expiry_year: expiryYear,
            cvv: cvv,
            balance: 0,
            status: 'active',
            pin_hash: pinHash
        })
        .select()
        .single();

    if (error) {
        console.error('Supabase insert error:', error);
        return res.status(500).json({ error: error.message });
    }

    res.json({
        success: true,
        card: {
            id: data.id,
            number: cardNumber,
            masked: data.card_number,
            holder: data.card_holder,
            email: data.email,
            expiry: `${data.expiry_month}/${data.expiry_year}`,
            cvv: cvv,
            balance: data.balance
        }
    });
});

// Get card details
app.get('/api/card/:cardId', async (req, res) => {
    const { cardId } = req.params;
    const { data, error } = await supabase
        .from('cards')
        .select('*')
        .eq('id', cardId)
        .single();

    if (error) return res.status(404).json({ error: 'Card not found' });
    res.json({ success: true, card: data });
});

// Request PIN change – send email with code
app.post('/api/card/request-pin-change', async (req, res) => {
    const { cardId, email } = req.body;
    if (!cardId || !email) return res.status(400).json({ error: 'Missing cardId or email' });

    const { data: card, error: fetchError } = await supabase
        .from('cards')
        .select('email')
        .eq('id', cardId)
        .single();

    if (fetchError) return res.status(404).json({ error: 'Card not found' });
    if (card.email !== email) return res.status(403).json({ error: 'Email does not match card record' });

    const code = generateCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    const { error: insertError } = await supabase
        .from('pin_reset')
        .insert({ card_id: cardId, code: code, expires_at: expiresAt });

    if (insertError) {
        console.error('Insert reset code error:', insertError);
        return res.status(500).json({ error: 'Failed to generate reset code' });
    }

    try {
        await transporter.sendMail({
            from: process.env.SMTP_FROM,
            to: email,
            subject: 'Your PIN Reset Code',
            text: `Your PIN reset code is: ${code}. It expires in 15 minutes.`
        });
        res.json({ success: true, message: 'Reset code sent to email' });
    } catch (mailError) {
        console.error('Email send error:', mailError);
        res.json({ success: true, message: 'If email exists, code was sent.' });
    }
});

// Change PIN – verify code and update
app.post('/api/card/change-pin', async (req, res) => {
    const { cardId, code, newPin } = req.body;
    if (!cardId || !code || !newPin) return res.status(400).json({ error: 'Missing required fields' });

    const { data: resetRecord, error: fetchError } = await supabase
        .from('pin_reset')
        .select('*')
        .eq('card_id', cardId)
        .eq('code', code)
        .single();

    if (fetchError || !resetRecord) return res.status(400).json({ error: 'Invalid or expired code' });

    const now = new Date();
    const expires = new Date(resetRecord.expires_at);
    if (now > expires) return res.status(400).json({ error: 'Code has expired' });

    const newPinHash = hashPin(newPin);
    const { error: updateError } = await supabase
        .from('cards')
        .update({ pin_hash: newPinHash })
        .eq('id', cardId);

    if (updateError) {
        console.error('Update PIN error:', updateError);
        return res.status(500).json({ error: 'Failed to update PIN' });
    }

    await supabase.from('pin_reset').delete().eq('id', resetRecord.id);
    res.json({ success: true, message: 'PIN changed successfully' });
});

// ============= MONCASH PAYMENT FLOW =============

// Initiate top‑up (real Moncash payment)
app.post('/api/card/topup', async (req, res) => {
    const { cardId, amount, phone, pin } = req.body;
    if (!cardId || !amount || !phone || !pin) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Verify PIN
    const { data: card, error: fetchError } = await supabase
        .from('cards')
        .select('balance, pin_hash')
        .eq('id', cardId)
        .single();

    if (fetchError) return res.status(404).json({ error: 'Card not found' });

    const inputHash = hashPin(pin);
    if (inputHash !== card.pin_hash) {
        return res.status(401).json({ error: 'Invalid PIN' });
    }

    // Generate unique reference
    const reference = uuidv4();

    // Store pending transaction
    const { error: pendingError } = await supabase
        .from('transactions')
        .insert({
            card_id: cardId,
            amount: amount,
            type: 'deposit',
            status: 'pending',
            reference: reference,
        });

    if (pendingError) {
        console.error('Pending transaction error:', pendingError);
        return res.status(500).json({ error: 'Failed to initiate payment' });
    }

    // Prepare Moncash payment request
    // (Check Moncash documentation for exact endpoint and payload)
    const paymentData = {
        amount: amount,
        phone: phone,
        reference: reference,
        redirect_url: `${process.env.APP_URL}/payment-callback.html?ref=${reference}`,
    };

    try {
        const moncashResponse = await axios.post(
            'https://api.moncash.com/v1/merchant/payments',
            paymentData,
            {
                headers: {
                    'Authorization': `Bearer ${process.env.MONCASH_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const paymentUrl = moncashResponse.data.payment_url;
        if (!paymentUrl) throw new Error('No payment URL returned');

        res.json({ success: true, redirectUrl: paymentUrl });
    } catch (error) {
        console.error('Moncash API error:', error.response?.data || error.message);
        await supabase
            .from('transactions')
            .update({ status: 'failed' })
            .eq('reference', reference);
        res.status(500).json({ error: 'Payment initiation failed' });
    }
});

// Webhook endpoint for Moncash callbacks
app.post('/api/moncash/webhook', async (req, res) => {
    const { reference, status } = req.body;

    if (!reference) {
        return res.status(400).send('Missing reference');
    }

    const { data: tx, error } = await supabase
        .from('transactions')
        .select('card_id, amount')
        .eq('reference', reference)
        .single();

    if (error || !tx) {
        console.error('Transaction not found for reference:', reference);
        return res.status(404).send('Transaction not found');
    }

    if (status === 'success') {
        // Update card balance
        const { data: card, error: fetchError } = await supabase
            .from('cards')
            .select('balance')
            .eq('id', tx.card_id)
            .single();

        if (!fetchError && card) {
            const newBalance = card.balance + tx.amount;
            await supabase
                .from('cards')
                .update({ balance: newBalance })
                .eq('id', tx.card_id);
        }

        await supabase
            .from('transactions')
            .update({ status: 'completed' })
            .eq('reference', reference);
    } else {
        await supabase
            .from('transactions')
            .update({ status: 'failed' })
            .eq('reference', reference);
    }

    res.status(200).send('OK');
});

// Get transaction history
app.get('/api/card/:cardId/transactions', async (req, res) => {
    const { cardId } = req.params;
    const { data, error } = await supabase
        .from('transactions')
        .select('*')
        .eq('card_id', cardId)
        .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, transactions: data });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`✅ Virtual card server running on port ${PORT}`));
