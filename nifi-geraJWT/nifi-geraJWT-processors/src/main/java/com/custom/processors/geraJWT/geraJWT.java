package com.custom.processors.geraJWT;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.expression.AttributeValueDecorator;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;

import java.util.*;

public class geraJWT extends AbstractProcessor {

    public static final PropertyDescriptor CLIENT_ID_PROPERTY = new PropertyDescriptor
            .Builder().name("Client ID")
            .description("ClientID da CAF")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final int DEFAULT_EXPIRATION_HOURS = 24;
    /* Alterado para que o tempo de expiração fique fixo em 24 horas
    public static final PropertyDescriptor EXPIRATION_PROPERTY = new PropertyDescriptor
            .Builder().name("Expiration")
            .description("Tempo de expiração em horas")
            .required(false)
            .addValidator(StandardValidators.POSITIVE_LONG_VALIDATOR)
            .build();*/

    public static final PropertyDescriptor PEOPLE_ID_PROPERTY = new PropertyDescriptor
            .Builder().name("People ID")
            .description("CPF")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor SECRET_KEY = new PropertyDescriptor
            .Builder().name("clientSecret")
            .description("Informe seu clientSecret")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final Relationship SUCCESS_RELATIONSHIP = new Relationship.Builder()
            .name("success")
            .description("Token JWT Gerado!")
            .build();

    public static final Relationship FAILURE_RELATIONSHIP = new Relationship.Builder()
            .name("failure")
            .description("Falha!")
            .build();

    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;

    String clientSecret;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        descriptors = new ArrayList<>();
        descriptors.add(CLIENT_ID_PROPERTY);
        /*descriptors.add(EXPIRATION_PROPERTY);*/
        descriptors.add(PEOPLE_ID_PROPERTY);
        descriptors.add(SECRET_KEY);
        descriptors = Collections.unmodifiableList(descriptors);

        relationships = new HashSet<>();
        relationships.add(SUCCESS_RELATIONSHIP);
        relationships.add(FAILURE_RELATIONSHIP);
        relationships = Collections.unmodifiableSet(relationships);

    }

    @Override
    public Set<Relationship> getRelationships() {
        return relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }

        String clientId = context.getProperty(CLIENT_ID_PROPERTY).getValue();
        /*int expirationHours = context.getProperty(EXPIRATION_PROPERTY).asInteger();*/
        String peopleId = context.getProperty(PEOPLE_ID_PROPERTY).getValue();
        clientSecret = context.getProperty(SECRET_KEY).getValue();

        getLogger().info("Valor do Client Secret: " + clientSecret);

        long expirationMillis = DEFAULT_EXPIRATION_HOURS * 3600 * 1000;
        String jwtToken = generateJwtToken(clientId, expirationMillis, peopleId);

        flowFile = session.putAttribute(flowFile, "jwt_token", jwtToken);
        session.transfer(flowFile, SUCCESS_RELATIONSHIP);
    }

    private String generateJwtToken(String clientId, long expirationMillis, String peopleId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMillis);

        return Jwts.builder()
                .setHeaderParam("alg", "HS256")
                .setHeaderParam("typ", "JWT")
                .setIssuer(clientId)
                .setExpiration(expiryDate)
                .claim("peopleId", peopleId)
                .signWith(SignatureAlgorithm.HS256, clientSecret.getBytes())
                .compact();
    }
}